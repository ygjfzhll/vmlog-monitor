from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import hashlib
import json
import secrets
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pymysql
from pymysql.cursors import DictCursor

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "config.yaml"
WEB_PATH = ROOT / "web" / "index.html"

STORM_WINDOW_SEC = 10
STORM_LIMIT = 30
STORM_PAUSE_SEC = 600
MSG_LIMIT = 400
ALERT_HISTORY = 100



def strip_comment(line):
    quote = None
    kept = []
    for char in line:
        if char in ('"', "'") and quote in (None, char):
            quote = None if quote else char
        if char == '#' and quote is None:
            break
        kept.append(char)
    return ''.join(kept).rstrip()


def load_config():
    cfg = {"victorialogs": {}, "feishu": {}, "mysql": {}, "server": {}}
    section = None
    text = CONFIG_PATH.read_text(encoding="utf-8-sig")
    for raw in text.splitlines():
        line = strip_comment(raw)
        if not line.strip():
            continue
        if not line.startswith(" ") and line.endswith(":"):
            section = line[:-1].strip()
            cfg.setdefault(section, {})
            continue
        if section and ":" in line:
            key, value = line.strip().split(":", 1)
            cfg[section][key.strip()] = value.strip().strip('"').strip("'")
    cfg["server"].setdefault("host", "127.0.0.1")
    cfg["server"].setdefault("port", "8787")
    return cfg


def logsql_quote(value):
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'





def log_time_epoch(value):
    text = str(value or "").strip()
    if not text:
        return None
    try:
        normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
        moment = datetime.fromisoformat(normalized)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=ZoneInfo("UTC"))
        return moment.timestamp()
    except ValueError:
        return None


def format_log_time(value):
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
        moment = datetime.fromisoformat(normalized)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=ZoneInfo("UTC"))
        return moment.astimezone(ZoneInfo("Asia/Shanghai")).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return text


def mask_text(value):
    value = re.sub(r"(?<!\d)1[3-9]\d{9}(?!\d)", "***", value)
    value = re.sub(r"(?i)(token|password|passwd|secret|authorization)(\s*[:=]\s*)(\S+)", r"\1\2***", value)
    return value



def hash_password(password):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120000).hex()
    return f"{salt}${digest}"


def verify_password(password, stored):
    salt, digest = stored.split("$", 1)
    check = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120000).hex()
    return secrets.compare_digest(check, digest)


def should_watch(rule):
    return bool(rule.get("enabled")) and not rule.get("paused")



def namespace_list(value):
    if isinstance(value, list):
        items = value
    else:
        items = re.split(r"[\n,，]+", str(value or ""))
    result = []
    for item in items:
        name = str(item).strip()
        if name and name not in result:
            result.append(name)
    return result


def container_groups(rule):
    grouped = {name: [] for name in namespace_list(rule.get("namespace"))}
    plain = []
    for item in rule.get("containers") or []:
        text = str(item).strip()
        if not text:
            continue
        if "/" in text:
            namespace, container = text.split("/", 1)
            namespace = namespace.strip()
            container = container.strip()
            if namespace and container:
                grouped.setdefault(namespace, []).append(container)
        else:
            plain.append(text)
    for namespace in list(grouped):
        for container in plain:
            if container not in grouped[namespace]:
                grouped[namespace].append(container)
    return grouped


def build_query(rule):
    groups = container_groups(rule)
    parts = []
    for namespace, containers in groups.items():
        if containers:
            pattern = "|".join(re.escape(item) for item in containers)
            parts.append("{namespace=%s,container_name=~%s}" % (logsql_quote(namespace), logsql_quote(pattern)))
        else:
            parts.append("{namespace=%s}" % logsql_quote(namespace))
    selector = " OR ".join(parts) if parts else "*"
    words = " OR ".join(f"i({logsql_quote(item)})" for item in rule["keywords"])
    return selector + " (" + words + ") | fields _time,_stream_id,_msg,kubernetes.pod_name,container_name,namespace"


class Store:
    def __init__(self, mysql_cfg):
        self.cfg = mysql_cfg
        self._ensure_schema()

    def connect(self):
        return pymysql.connect(
            host=self.cfg.get("host", "127.0.0.1"),
            port=int(self.cfg.get("port", "3306")),
            user=self.cfg["user"],
            password=self.cfg.get("password", ""),
            database=self.cfg["database"],
            charset="utf8mb4",
            cursorclass=DictCursor,
            autocommit=True,
        )

    def _ensure_schema(self):
        database = self.cfg["database"]
        bootstrap = pymysql.connect(
            host=self.cfg.get("host", "127.0.0.1"),
            port=int(self.cfg.get("port", "3306")),
            user=self.cfg["user"],
            password=self.cfg.get("password", ""),
            charset="utf8mb4",
            autocommit=True,
        )
        try:
            with bootstrap.cursor() as cursor:
                cursor.execute(
                    f"CREATE DATABASE IF NOT EXISTS `{database}` DEFAULT CHARACTER SET utf8mb4"
                )
        finally:
            bootstrap.close()
        with self.connect() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS rules (
                        id VARCHAR(32) PRIMARY KEY,
                        name VARCHAR(80) NOT NULL,
                        namespace_name VARCHAR(80) NOT NULL,
                        containers TEXT NOT NULL,
                        keywords TEXT NOT NULL,
                        cooldown_sec INT NOT NULL,
                        enabled TINYINT NOT NULL,
                        webhook VARCHAR(300) NOT NULL DEFAULT '',
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                    )
                    """
                )
                self._ensure_column(cursor, "rules", "webhook", "VARCHAR(300) NOT NULL DEFAULT ''")
                self._ensure_column(cursor, "rules", "matched_count", "BIGINT NOT NULL DEFAULT 0")
                self._ensure_column(cursor, "rules", "paused", "TINYINT NOT NULL DEFAULT 0")
                self._ensure_column(cursor, "rules", "source_id", "VARCHAR(32) NOT NULL DEFAULT ''")
                self._ensure_column(cursor, "rules", "webhook_id", "VARCHAR(32) NOT NULL DEFAULT ''")
                cursor.execute("ALTER TABLE rules MODIFY namespace_name TEXT NOT NULL")
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS webhooks (
                        id VARCHAR(32) PRIMARY KEY,
                        name VARCHAR(80) NOT NULL,
                        hook_url VARCHAR(300) NOT NULL
                    )
                    """
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS log_sources (
                        id VARCHAR(32) PRIMARY KEY,
                        name VARCHAR(80) NOT NULL,
                        base_url VARCHAR(300) NOT NULL,
                        account_id VARCHAR(20) NOT NULL DEFAULT '1',
                        project_id VARCHAR(20) NOT NULL DEFAULT '1'
                    )
                    """
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS alerts (
                        id BIGINT PRIMARY KEY AUTO_INCREMENT,
                        created_at DATETIME NOT NULL,
                        project VARCHAR(80) NOT NULL,
                        keyword_text VARCHAR(80) NOT NULL,
                        namespace_name VARCHAR(80) NULL,
                        container_name VARCHAR(80) NULL,
                        pod_name VARCHAR(160) NULL,
                        log_time VARCHAR(40) NULL,
                        message TEXT NULL,
                        delivered TINYINT NOT NULL,
                        error_text VARCHAR(300) NULL,
                        body TEXT NULL,
                        rule_id VARCHAR(32) NOT NULL DEFAULT '',
                        INDEX idx_alerts_created (created_at),
                        INDEX idx_alerts_rule (rule_id, id)
                    )
                    """
                )
                self._ensure_column(cursor, "alerts", "rule_id", "VARCHAR(32) NOT NULL DEFAULT ''")
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS container_hits (
                        rule_id VARCHAR(32) NOT NULL,
                        container_name VARCHAR(120) NOT NULL,
                        hit_count BIGINT NOT NULL DEFAULT 0,
                        PRIMARY KEY (rule_id, container_name)
                    )
                    """
                )

                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        id VARCHAR(32) PRIMARY KEY,
                        username VARCHAR(40) NOT NULL UNIQUE,
                        display_name VARCHAR(40) NOT NULL,
                        password_hash VARCHAR(200) NOT NULL,
                        is_admin TINYINT NOT NULL DEFAULT 0,
                        enabled TINYINT NOT NULL DEFAULT 1,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS project_members (
                        user_id VARCHAR(32) NOT NULL,
                        rule_id VARCHAR(32) NOT NULL,
                        PRIMARY KEY (user_id, rule_id)
                    )
                    """
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit_logs (
                        id BIGINT PRIMARY KEY AUTO_INCREMENT,
                        created_at DATETIME NOT NULL,
                        user_name VARCHAR(40) NOT NULL,
                        action_name VARCHAR(40) NOT NULL,
                        rule_id VARCHAR(32) NOT NULL DEFAULT '',
                        detail VARCHAR(300) NOT NULL DEFAULT ''
                    )
                    """
                )
                cursor.execute(
                    """
                    UPDATE alerts a
                    JOIN rules r ON a.project = r.name
                    SET a.rule_id = r.id
                    WHERE a.rule_id = ''
                    """
                )


    @staticmethod
    def _ensure_column(cursor, table, column, definition):
        cursor.execute(f"SHOW COLUMNS FROM {table} LIKE %s", (column,))
        if cursor.fetchone() is None:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")




    def ensure_default_source(self, url, account_id, project_id):
        with self.connect() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT id FROM log_sources LIMIT 1")
                row = cursor.fetchone()
                if row:
                    source_id = row["id"]
                else:
                    source_id = "default"
                    cursor.execute(
                        "INSERT INTO log_sources (id, name, base_url, account_id, project_id) VALUES (%s, %s, %s, %s, %s)",
                        (source_id, "默认日志源", url or "http://127.0.0.1:9428", account_id or "1", project_id or "1"),
                    )
                cursor.execute("UPDATE rules SET source_id=%s WHERE source_id=''", (source_id,))
        return source_id

    def list_sources(self):
        with self.connect() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT id, name, base_url, account_id, project_id FROM log_sources ORDER BY name, id")
                return list(cursor.fetchall())

    def save_source(self, source):
        with self.connect() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO log_sources (id, name, base_url, account_id, project_id)
                    VALUES (%s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE name=VALUES(name), base_url=VALUES(base_url),
                        account_id=VALUES(account_id), project_id=VALUES(project_id)
                    """,
                    (source["id"], source["name"], source["url"], source["account_id"], source["project_id"]),
                )

    def delete_source(self, source_id):
        with self.connect() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) AS total FROM rules WHERE source_id=%s", (source_id,))
                if cursor.fetchone()["total"]:
                    raise ValueError("还有项目在使用这个日志源")
                cursor.execute("SELECT COUNT(*) AS total FROM log_sources")
                if cursor.fetchone()["total"] <= 1:
                    raise ValueError("至少保留一个日志源")
                cursor.execute("DELETE FROM log_sources WHERE id=%s", (source_id,))


    def list_webhooks(self):
        with self.connect() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT id, name, hook_url FROM webhooks ORDER BY name, id")
                return list(cursor.fetchall())

    def save_webhook(self, item):
        with self.connect() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO webhooks (id, name, hook_url) VALUES (%s, %s, %s)
                    ON DUPLICATE KEY UPDATE name=VALUES(name), hook_url=VALUES(hook_url)
                    """,
                    (item["id"], item["name"], item["url"]),
                )
                cursor.execute("UPDATE rules SET webhook=%s WHERE webhook_id=%s", (item["url"], item["id"]))

    def delete_webhook(self, webhook_id):
        with self.connect() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) AS total FROM rules WHERE webhook_id=%s", (webhook_id,))
                if cursor.fetchone()["total"]:
                    raise ValueError("还有项目在使用这个 Webhook")
                cursor.execute("DELETE FROM webhooks WHERE id=%s", (webhook_id,))

    def ensure_admin(self, username, password):
        with self.connect() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) AS total FROM users")
                if cursor.fetchone()["total"]:
                    return None
        generated = False
        if not password:
            password = secrets.token_urlsafe(9)
            generated = True
        self.create_user(username or "admin", "管理员", password, True, [])
        return password if generated else None

    def create_user(self, username, display_name, password, is_admin, rule_ids):
        user_id = str(int(time.time() * 1000))
        with self.connect() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO users (id, username, display_name, password_hash, is_admin, enabled)
                    VALUES (%s, %s, %s, %s, %s, 1)
                    """,
                    (user_id, username, display_name, hash_password(password), 1 if is_admin else 0),
                )
        self.set_membership(user_id, rule_ids)
        return user_id

    def update_user(self, user_id, display_name, is_admin, enabled, rule_ids):
        with self.connect() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE users SET display_name=%s, is_admin=%s, enabled=%s WHERE id=%s
                    """,
                    (display_name, 1 if is_admin else 0, 1 if enabled else 0, user_id),
                )
        self.set_membership(user_id, rule_ids)

    def set_password(self, user_id, password):
        with self.connect() as conn:
            with conn.cursor() as cursor:
                cursor.execute("UPDATE users SET password_hash=%s WHERE id=%s", (hash_password(password), user_id))

    def set_membership(self, user_id, rule_ids):
        with self.connect() as conn:
            with conn.cursor() as cursor:
                cursor.execute("DELETE FROM project_members WHERE user_id=%s", (user_id,))
                for rule_id in rule_ids:
                    cursor.execute(
                        "INSERT IGNORE INTO project_members (user_id, rule_id) VALUES (%s, %s)",
                        (user_id, rule_id),
                    )


    def set_rule_members(self, rule_id, user_ids):
        with self.connect() as conn:
            with conn.cursor() as cursor:
                cursor.execute("DELETE FROM project_members WHERE rule_id=%s", (rule_id,))
                for user_id in user_ids:
                    cursor.execute(
                        "INSERT IGNORE INTO project_members (user_id, rule_id) VALUES (%s, %s)",
                        (user_id, rule_id),
                    )


    def delete_user(self, user_id):
        users = self.list_users()
        target = next((user for user in users if user["id"] == user_id), None)
        if not target:
            raise ValueError("用户不存在")
        if target["is_admin"] and sum(1 for user in users if user["is_admin"]) <= 1:
            raise ValueError("至少保留一个管理员")
        with self.connect() as conn:
            with conn.cursor() as cursor:
                cursor.execute("DELETE FROM project_members WHERE user_id=%s", (user_id,))
                cursor.execute("DELETE FROM users WHERE id=%s", (user_id,))

    def list_users(self):
        with self.connect() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT id, username, display_name, is_admin, enabled FROM users ORDER BY created_at, id"
                )
                users = cursor.fetchall()
                cursor.execute("SELECT user_id, rule_id FROM project_members")
                grouped = {}
                for row in cursor.fetchall():
                    grouped.setdefault(row["user_id"], []).append(row["rule_id"])
        result = []
        for user in users:
            result.append({
                "id": user["id"],
                "username": user["username"],
                "display_name": user["display_name"],
                "is_admin": bool(user["is_admin"]),
                "enabled": bool(user["enabled"]),
                "rule_ids": grouped.get(user["id"], []),
            })
        return result

    def authenticate(self, username, password):
        with self.connect() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT id, username, display_name, password_hash, is_admin, enabled FROM users WHERE username=%s",
                    (username,),
                )
                user = cursor.fetchone()
        if not user or not user["enabled"] or not verify_password(password, user["password_hash"]):
            return None
        return {
            "id": user["id"],
            "username": user["username"],
            "display_name": user["display_name"],
            "is_admin": bool(user["is_admin"]),
        }

    def member_rule_ids(self, user_id):
        with self.connect() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT rule_id FROM project_members WHERE user_id=%s", (user_id,))
                return {row["rule_id"] for row in cursor.fetchall()}

    def audit(self, user_name, action, rule_id="", detail=""):
        with self.connect() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO audit_logs (created_at, user_name, action_name, rule_id, detail)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (time.strftime("%Y-%m-%d %H:%M:%S"), user_name, action, rule_id or "", detail[:300]),
                )


    def list_rules(self):
        with self.connect() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id, name, namespace_name, containers, keywords, cooldown_sec, enabled, webhook, matched_count, paused, source_id, webhook_id
                    FROM rules ORDER BY updated_at DESC, id DESC
                    """
                )
                rules = [self._rule_from_row(row) for row in cursor.fetchall()]
        hits = self.container_hit_map()
        sources = {item["id"]: item for item in self.list_sources()}
        hooks = {item["id"]: item for item in self.list_webhooks()}
        for rule in rules:
            rule["container_hits"] = hits.get(rule["id"], {})
            source = sources.get(rule.get("source_id")) or {}
            rule["source_name"] = source.get("name") or ""
            rule["source_url"] = source.get("base_url") or ""
            rule["account_id"] = source.get("account_id") or "1"
            rule["project_id"] = source.get("project_id") or "1"
            hook = hooks.get(rule.get("webhook_id"))
            if hook:
                rule["webhook"] = hook.get("hook_url") or rule.get("webhook") or ""
                rule["webhook_name"] = hook.get("name") or ""
        return rules

    def save_rule(self, rule):
        with self.connect() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO rules (id, name, namespace_name, containers, keywords, cooldown_sec, enabled, webhook, webhook_id, paused, source_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        name=VALUES(name), namespace_name=VALUES(namespace_name),
                        containers=VALUES(containers), keywords=VALUES(keywords),
                        cooldown_sec=VALUES(cooldown_sec), enabled=VALUES(enabled),
                        webhook=VALUES(webhook),
                        webhook_id=VALUES(webhook_id),
                        paused=VALUES(paused),
                        source_id=VALUES(source_id)
                    """,
                    (
                        rule["id"], rule["name"], json.dumps(namespace_list(rule.get("namespace")), ensure_ascii=False),
                        json.dumps(rule["containers"], ensure_ascii=False),
                        json.dumps(rule["keywords"], ensure_ascii=False),
                        rule["cooldown_sec"], 1 if rule["enabled"] else 0,
                        rule.get("webhook", ""),
                        rule.get("webhook_id") or "",
                        1 if rule.get("paused") else 0,
                        rule.get("source_id") or "",
                    ),
                )

    def delete_rule(self, rule_id):
        with self.connect() as conn:
            with conn.cursor() as cursor:
                cursor.execute("DELETE FROM rules WHERE id=%s", (rule_id,))
                cursor.execute("DELETE FROM project_members WHERE rule_id=%s", (rule_id,))

    def insert_alert(self, alert):
        with self.connect() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO alerts (
                        created_at, project, keyword_text, namespace_name, container_name,
                        pod_name, log_time, message, delivered, error_text, body, rule_id
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        alert["created_at"], alert["project"], alert["keyword"],
                        alert.get("namespace"), alert.get("container"), alert.get("pod"),
                        alert.get("log_time"), alert.get("message"),
                        1 if alert["delivered"] else 0, alert.get("error") or None, alert["text"],
                        alert.get("rule_id") or "",
                    ),
                )
                return cursor.lastrowid

    def add_matches(self, rule_id, count, by_container=None):
        if count <= 0 and not by_container:
            return
        with self.connect() as conn:
            with conn.cursor() as cursor:
                if count > 0:
                    cursor.execute("UPDATE rules SET matched_count = matched_count + %s WHERE id=%s", (count, rule_id))
                for name, hits in (by_container or {}).items():
                    if hits <= 0:
                        continue
                    cursor.execute(
                        """
                        INSERT INTO container_hits (rule_id, container_name, hit_count)
                        VALUES (%s, %s, %s)
                        ON DUPLICATE KEY UPDATE hit_count = hit_count + VALUES(hit_count)
                        """,
                        (rule_id, name[:120], hits),
                    )

    def container_hit_map(self):
        with self.connect() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT rule_id, container_name, hit_count FROM container_hits")
                grouped = {}
                for row in cursor.fetchall():
                    grouped.setdefault(row["rule_id"], {})[row["container_name"]] = int(row["hit_count"])
                return grouped


    def home_summary(self, rule_ids, range_key="1h", start_at=None, end_at=None):
        spans = {"1h": timedelta(hours=1), "6h": timedelta(hours=6), "24h": timedelta(hours=24), "7d": timedelta(days=7)}
        if start_at and end_at:
            start, end = start_at, end_at
            range_key = "custom"
        elif range_key not in spans:
            range_key = "1h"
            start = (datetime.now() - spans[range_key]).strftime("%Y-%m-%d %H:%M:%S")
            end = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        else:
            start = (datetime.now() - spans[range_key]).strftime("%Y-%m-%d %H:%M:%S")
            end = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if not rule_ids:
            return {"watching": 0, "paused": 0, "alerts_today": 0, "delivered": 0, "failed": 0, "sources": 0, "attention": [], "range": range_key}
        marks = ",".join(["%s"] * len(rule_ids))
        with self.connect() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    f"SELECT delivered, COUNT(*) AS total FROM alerts WHERE created_at>=%s AND created_at<=%s AND rule_id IN ({marks}) GROUP BY delivered",
                    [start, end, *rule_ids],
                )
                delivered = failed = 0
                for row in cursor.fetchall():
                    if row["delivered"]:
                        delivered = int(row["total"])
                    else:
                        failed = int(row["total"])
                cursor.execute(
                    f"""
                    SELECT project, keyword_text, created_at, error_text
                    FROM alerts WHERE created_at>=%s AND created_at<=%s AND rule_id IN ({marks}) AND delivered=0
                    ORDER BY id DESC LIMIT 8
                    """,
                    [start, end, *rule_ids],
                )
                failed_rows = cursor.fetchall()
                cursor.execute(
                    f"""
                    SELECT project, COUNT(*) AS total
                    FROM alerts WHERE created_at>=%s AND created_at<=%s AND rule_id IN ({marks})
                    GROUP BY project ORDER BY total DESC LIMIT 5
                    """,
                    [start, end, *rule_ids],
                )
                hot = cursor.fetchall()
        attention = []
        for row in failed_rows:
            created = row["created_at"]
            attention.append({
                "project": row["project"],
                "detail": "飞书发送失败" + (("：" + row["error_text"]) if row["error_text"] else ""),
                "time": created.strftime("%H:%M") if hasattr(created, "strftime") else str(created),
            })
        for row in hot:
            if int(row["total"]) >= 10:
                attention.append({"project": row["project"], "detail": f"今日已告警 {int(row['total'])} 次", "time": "今天"})
        return {
            "delivered": delivered,
            "failed": failed,
            "alerts_today": delivered + failed,
            "attention": attention[:8],
            "range": range_key,
        }

    def list_alerts(self, rule_id="", container="", keyword="", limit=200):
        if not rule_id:
            return []
        sql = """
            SELECT id, created_at, project, keyword_text, namespace_name, container_name,
                   pod_name, log_time, message, delivered, error_text, body, rule_id
            FROM alerts WHERE rule_id=%s
        """
        params = [rule_id]
        if container:
            sql += " AND container_name=%s"
            params.append(container)
        if keyword:
            sql += " AND keyword_text=%s"
            params.append(keyword)
        sql += " ORDER BY id DESC LIMIT %s"
        params.append(min(max(int(limit), 1), 500))
        with self.connect() as conn:
            with conn.cursor() as cursor:
                cursor.execute(sql, params)
                rows = []
                for row in cursor.fetchall():
                    created = row["created_at"]
                    rows.append({
                        "id": row["id"],
                        "time": created.strftime("%Y-%m-%d %H:%M:%S") if hasattr(created, "strftime") else str(created),
                        "project": row["project"],
                        "keyword": row["keyword_text"],
                        "namespace": row["namespace_name"] or "",
                        "container": row["container_name"] or "",
                        "pod": row["pod_name"] or "",
                        "log_time": row["log_time"] or "",
                        "message": row["message"] or "",
                        "delivered": bool(row["delivered"]),
                        "error": row["error_text"] or "",
                        "text": row["body"] or "",
                        "rule_id": row.get("rule_id") or "",
                    })
                return rows

    @staticmethod
    def _rule_from_row(row):
        return {
            "id": row["id"],
            "name": row["name"],
            "namespace": namespace_list(json.loads(row["namespace_name"]) if str(row["namespace_name"]).lstrip().startswith("[") else row["namespace_name"]),
            "containers": json.loads(row["containers"] or "[]"),
            "keywords": json.loads(row["keywords"] or "[]"),
            "cooldown_sec": int(row["cooldown_sec"]),
            "enabled": bool(row["enabled"]),
            "paused": bool(row.get("paused")),
            "webhook": row.get("webhook") or "",
            "matched": int(row.get("matched_count") or 0),
            "source_id": row.get("source_id") or "",
            "webhook_id": row.get("webhook_id") or "",
        }


class Monitor:
    def __init__(self, config):
        self.config = config
        self.store = Store(config["mysql"])
        self.lock = threading.Lock()
        self.rules = self.store.list_rules()
        self.workers = {}
        self.sessions = {}
        self.started_at = time.time()


    def login(self, username, password):
        user = self.store.authenticate(username, password)
        if not user:
            raise ValueError("账号或密码不正确")
        token = secrets.token_urlsafe(32)
        self.sessions[token] = {**user, "expires": time.time() + 7 * 86400}
        return token, user

    def logout(self, token):
        self.sessions.pop(token, None)

    def session_user(self, token):
        item = self.sessions.get(token or "")
        if not item or item["expires"] < time.time():
            self.sessions.pop(token or "", None)
            return None
        return {key: item[key] for key in ("id", "username", "display_name", "is_admin")}

    def allowed_rule_ids(self, user):
        if user["is_admin"]:
            with self.lock:
                return {rule["id"] for rule in self.rules}
        return self.store.member_rule_ids(user["id"])

    def can_access(self, user, rule_id):
        return rule_id in self.allowed_rule_ids(user)


    def list_containers(self, source_id, namespace):
        namespaces = namespace_list(namespace)
        if not namespaces:
            raise ValueError("请先填写命名空间")
        source = next((item for item in self.store.list_sources() if item["id"] == source_id), None)
        if not source:
            raise ValueError("请先选择日志源")
        found = []
        seen = set()
        for namespace in namespaces:
            query = "_time:6h {namespace=%s} | stats by (container_name) count() as hits | sort by (hits) desc" % logsql_quote(namespace)
            url = source["base_url"].rstrip("/") + "/select/logsql/query"
            data = urllib.parse.urlencode({"query": query}).encode()
            request = urllib.request.Request(
                url,
                data=data,
                headers={
                    "AccountID": str(source["account_id"]),
                    "ProjectID": str(source["project_id"]),
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    raw = response.read().decode("utf-8", errors="replace")
            except Exception as exc:
                raise RuntimeError("日志源查询失败") from exc
            for line in raw.splitlines():
                if not line.strip():
                    continue
                item = json.loads(line)
                name = str(item.get("container_name") or "").strip()
                key = (namespace, name)
                if name and key not in seen:
                    seen.add(key)
                    found.append({"namespace": namespace, "name": name})
        return found

    def start(self):
        for rule in list(self.rules):
            if should_watch(rule):
                self._start_worker(rule)


    def home(self, user, range_key="1h", start_at=None, end_at=None):
        allowed = self.allowed_rule_ids(user)
        with self.lock:
            rules = [rule for rule in self.rules if rule["id"] in allowed]
        summary = self.store.home_summary([rule["id"] for rule in rules], range_key, start_at, end_at)
        summary["watching"] = sum(1 for rule in rules if should_watch(rule))
        summary["paused"] = sum(1 for rule in rules if rule.get("paused"))
        summary["sources"] = len({rule.get("source_id") for rule in rules if rule.get("source_id")})
        for rule in rules:
            if rule.get("paused"):
                summary["attention"].append({"project": rule["name"], "detail": "监控已暂停", "time": ""})
        summary["attention"] = summary["attention"][:8]
        return summary

    def snapshot(self, user):
        allowed = self.allowed_rule_ids(user)
        with self.lock:
            workers = {key: value.public_state() for key, value in self.workers.items()}
            rules = []
            for rule in self.rules:
                if rule["id"] not in allowed:
                    continue
                item = dict(rule)
                item["runtime"] = workers.get(rule["id"], {"state": "stopped"})
                rules.append(item)
        return {
            "rules": rules,
            "victorialogs": self.config["victorialogs"].get("url", ""),
            "started_at": self.started_at,
        }

    def set_paused(self, rule_id, paused, user=None):
        with self.lock:
            current = next((rule for rule in self.rules if rule["id"] == rule_id), None)
        if not current:
            raise ValueError("项目不存在")
        current = dict(current)
        current["paused"] = bool(paused)
        self.store.save_rule(current)
        with self.lock:
            for index, rule in enumerate(self.rules):
                if rule["id"] == rule_id:
                    self.rules[index] = current
                    break
        self._restart_worker(current)
        if user:
            self.store.audit(user["display_name"], "继续监控" if not current["paused"] else "暂停监控", rule_id, current["name"])
        return current

    def upsert(self, payload, rule_id=None, user=None):
        rule = self._normalize(payload, rule_id)
        if rule.get("paused") is None or not rule.get("source_id"):
            with self.lock:
                current = next((item for item in self.rules if item["id"] == rule["id"]), None)
            if rule.get("paused") is None:
                rule["paused"] = bool(current.get("paused")) if current else False
            if not rule.get("source_id"):
                rule["source_id"] = (current or {}).get("source_id") or ""
            if "webhook_id" not in payload and current:
                rule["webhook_id"] = current.get("webhook_id") or ""
            if rule.get("webhook_id"):
                hook = next((item for item in self.store.list_webhooks() if item["id"] == rule["webhook_id"]), None)
                if hook:
                    rule["webhook"] = hook["hook_url"]
        self.store.save_rule(rule)
        if user:
            self.store.audit(user["display_name"], "保存项目", rule["id"], rule["name"])
        with self.lock:
            replaced = False
            for index, current in enumerate(self.rules):
                if current["id"] == rule["id"]:
                    self.rules[index] = rule
                    replaced = True
                    break
            if not replaced:
                self.rules.insert(0, rule)
        self._restart_worker(rule)
        return rule

    def delete(self, rule_id, user=None):
        with self.lock:
            current = next((rule for rule in self.rules if rule["id"] == rule_id), None)
        self._stop_worker(rule_id)
        self.store.delete_rule(rule_id)
        with self.lock:
            self.rules = [rule for rule in self.rules if rule["id"] != rule_id]
        if user and current:
            self.store.audit(user["display_name"], "删除项目", rule_id, current["name"])

    def send_feishu(self, text, webhook=None):
        webhook = (webhook or "").strip() or self.config.get("feishu", {}).get("webhook", "")
        if not webhook:
            raise RuntimeError("未配置飞书 webhook")
        body = json.dumps({"msg_type": "text", "content": {"text": text}}, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(webhook, data=body, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                raw = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"飞书返回 {exc.code}: {detail[:300]}") from exc
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = {}
        code = parsed.get("code", parsed.get("StatusCode"))
        if code not in (0, None):
            raise RuntimeError(f"飞书发送失败: {raw[:300]}")
        return parsed

    def record(self, alert):
        alert["created_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        self.store.insert_alert(alert)

    def _normalize(self, payload, rule_id):
        name = str(payload.get("name", "")).strip()
        namespaces = self._split(payload.get("namespace", ""))[:50]
        containers = self._split(payload.get("containers", ""))
        keywords = self._split(payload.get("keywords", ""))
        if not name or not namespaces or not keywords:
            raise ValueError("项目名、命名空间和至少一个关键字都要填写")
        try:
            cooldown = int(payload.get("cooldown_sec", 300))
        except (TypeError, ValueError):
            cooldown = 300
        return {
            "id": rule_id or str(int(time.time() * 1000)),
            "name": name[:40],
            "namespace": namespaces,
            "containers": containers[:500],
            "keywords": keywords[:30],
            "cooldown_sec": min(max(cooldown, 30), 86400),
            "enabled": bool(payload.get("enabled", True)),
            "paused": bool(payload["paused"]) if "paused" in payload else None,
            "webhook": str(payload.get("webhook", "")).strip()[:300],
            "source_id": str(payload.get("source_id", "")).strip()[:32],
            "webhook_id": str(payload.get("webhook_id", "")).strip()[:32],
        }

    @staticmethod
    def _split(value):
        text = "\n".join(str(item) for item in value) if isinstance(value, list) else str(value or "")
        result = []
        for piece in re.split(r"[\n,，]+", text):
            item = piece.strip()
            if item and item not in result:
                result.append(item[:80])
        return result

    def _restart_worker(self, rule):
        self._stop_worker(rule["id"])
        if should_watch(rule):
            self._start_worker(rule)

    def _start_worker(self, rule):
        worker = TailWorker(self, rule)
        with self.lock:
            self.workers[rule["id"]] = worker
        worker.start()

    def _stop_worker(self, rule_id):
        with self.lock:
            worker = self.workers.pop(rule_id, None)
        if worker:
            worker.stop()
            worker.flush_matches()


class TailWorker(threading.Thread):
    def __init__(self, monitor, rule):
        super().__init__(daemon=True, name=f"tail-{rule['id']}")
        self.monitor = monitor
        self.rule = rule
        self.stop_event = threading.Event()
        self.state_lock = threading.Lock()
        self.state = "starting"
        self.last_error = ""
        self.matched_base = int(rule.get("matched") or 0)
        self.pending_matches = 0
        self.container_base = dict(rule.get("container_hits") or {})
        self.pending_by = {}
        self.matched = self.matched_base
        self.last_match = None
        self.last_flush = time.time()
        self.buckets = {}
        self.seen = []
        self.reconnect = False
        self.last_wall = time.time()
        self.alert_after = time.time() - 5

    def public_state(self):
        with self.state_lock:
            return {
                "state": self.state,
                "last_error": self.last_error,
                "matched": self.matched,
                "container_hits": self._combined_hits(),
                "last_match": self.last_match,
            }

    def stop(self):
        self.stop_event.set()

    def run(self):
        delay = 2
        while not self.stop_event.is_set():
            try:
                self._set(state="running", last_error="")
                self._tail()
                delay = 2
            except Exception as exc:
                if self.stop_event.is_set():
                    break
                self.reconnect = True
                self._set(state="reconnecting", last_error=str(exc)[:240])
                self.stop_event.wait(delay)
                delay = min(delay * 2, 30)
        self.flush_matches()
        self._set(state="stopped")

    def _set(self, **updates):
        with self.state_lock:
            for key, value in updates.items():
                setattr(self, key, value)

    def _combined_hits(self):
        merged = dict(self.container_base)
        for name, hits in self.pending_by.items():
            merged[name] = merged.get(name, 0) + hits
        return merged

    def flush_matches(self):
        count = self.pending_matches
        by_container = dict(self.pending_by)
        if count <= 0 and not by_container:
            return
        self.pending_matches = 0
        self.pending_by = {}
        self.last_flush = time.time()
        try:
            self.monitor.store.add_matches(self.rule["id"], count, by_container)
            self.matched_base += count
            for name, hits in by_container.items():
                self.container_base[name] = self.container_base.get(name, 0) + hits
        except Exception as exc:
            self.pending_matches += count
            for name, hits in by_container.items():
                self.pending_by[name] = self.pending_by.get(name, 0) + hits
            self._set(last_error=str(exc)[:240])

    def _note_match(self, container):
        name = container or "未识别容器"
        self.pending_matches += 1
        self.pending_by[name] = self.pending_by.get(name, 0) + 1
        self._set(matched=self.matched_base + self.pending_matches, last_match=time.time())
        if self.pending_matches >= 30 or time.time() - self.last_flush >= 5:
            self.flush_matches()

    def _tail(self):
        logs = {
            "url": self.rule.get("source_url") or self.monitor.config["victorialogs"].get("url", ""),
            "account_id": self.rule.get("account_id") or self.monitor.config["victorialogs"].get("account_id", "1"),
            "project_id": self.rule.get("project_id") or self.monitor.config["victorialogs"].get("project_id", "1"),
        }
        url = logs["url"].rstrip("/") + "/select/logsql/tail"
        payload = {
            "query": build_query(self.rule),
            "refresh_interval": "1s",
            "offset": "2s",
        }
        if self.reconnect:
            gap = max(30, int(time.time() - self.last_wall) + 15)
            payload["start_offset"] = f"{min(gap, 1800)}s"
        form = urllib.parse.urlencode(payload).encode()
        request = urllib.request.Request(
            url,
            data=form,
            headers={
                "AccountID": logs.get("account_id", "1"),
                "ProjectID": logs.get("project_id", "1"),
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            while not self.stop_event.is_set():
                try:
                    line = response.readline()
                except socket.timeout:
                    continue
                if not line:
                    raise ConnectionError("实时连接已断开")
                self.last_wall = time.time()
                self._handle_line(line)

    def _handle_line(self, line):
        try:
            entry = json.loads(line.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return
        message = mask_text(str(entry.get("_msg", ""))[:MSG_LIMIT])
        keyword = self._matched_keyword(message)
        if not keyword:
            return
        pod = str(entry.get("kubernetes.pod_name", ""))
        container = str(entry.get("container_name", ""))
        log_epoch = log_time_epoch(entry.get("_time"))
        if log_epoch is not None and log_epoch < self.alert_after:
            return
        when = format_log_time(entry.get("_time", ""))
        seen_key = (when, keyword, pod, message[:80])
        if seen_key in self.seen:
            return
        self.seen.append(seen_key)
        del self.seen[:-1000]
        self._note_match(container)
        now = time.time()
        bucket = self.buckets.setdefault(keyword, {"count": 0, "last_sent": 0})
        bucket["count"] += 1
        if bucket["last_sent"] and now - bucket["last_sent"] < self.rule["cooldown_sec"]:
            return
        count = bucket["count"]
        bucket["count"] = 0
        bucket["last_sent"] = now
        ns_text = "、".join(namespace_list(self.rule.get("namespace")))
        log_namespace = str(entry.get("namespace") or ns_text)
        place = f"{log_namespace} / {container or '未识别容器'} / {pod or '未识别实例'}"
        if count == 1:
            text = (
                "【日志告警】\n"
                f"项目名称：{self.rule['name']}\n"
                f"命中关键字：{keyword}\n"
                f"位置：{place}\n"
                f"时间：{when}\n"
                f"日志：{message}"
            )
        else:
            text = (
                "【日志汇总】\n"
                f"项目名称：{self.rule['name']}\n"
                f"命中关键字：{keyword}\n"
                f"约 {self.rule['cooldown_sec']} 秒内共 {count} 次，已合并成一条。\n"
                f"位置：{place}\n"
                f"时间：{when}\n"
                f"日志：{message}"
            )
        self._emit(text, keyword, message, container, pod, when, count, log_namespace)

    def _matched_keyword(self, message):
        folded = message.lower()
        for keyword in self.rule["keywords"]:
            if keyword.lower() in folded:
                return keyword
        return ""

    def _emit(self, text, keyword, message, container, pod, when, count=1, log_namespace=""):
        delivered = True
        error = ""
        try:
            self.monitor.send_feishu(text, self.rule.get("webhook"))
        except Exception as exc:
            delivered = False
            error = str(exc)[:240]
            self._set(last_error=error)
        self.monitor.record({
            "project": self.rule["name"],
            "rule_id": self.rule["id"],
            "keyword": keyword,
            "namespace": (log_namespace or "")[:80],
            "container": container,
            "pod": pod,
            "log_time": when,
            "message": message,
            "delivered": delivered,
            "error": error,
            "text": text,
        })


class Handler(BaseHTTPRequestHandler):
    monitor = None

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/":
            self._send(200, "text/html; charset=utf-8", WEB_PATH.read_bytes())
            return
        user = self._require_user()
        if not user:
            return
        if path == "/api/me":
            self._send_json(user)
            return
        if path == "/api/status":
            self._send_json(self.monitor.snapshot(user))
            return
        if path == "/api/home":
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            range_key = (query.get("range") or ["1h"])[0]
            start_at = (query.get("start") or [""])[0].replace("T", " ")
            end_at = (query.get("end") or [""])[0].replace("T", " ")
            if start_at and len(start_at) == 16:
                start_at += ":00"
            if end_at and len(end_at) == 16:
                end_at += ":00"
            if range_key == "custom" and start_at and end_at and start_at > end_at:
                self._send_json({"error": "开始时间不能晚于结束时间"}, 400)
                return
            self._send_json(self.monitor.home(user, range_key, start_at or None, end_at or None))
            return
        if path == "/api/containers":
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            try:
                names = self.monitor.list_containers((query.get("source_id") or [""])[0], (query.get("namespace") or [""])[0])
                self._send_json(names)
            except ValueError as exc:
                self._send_json({"error": str(exc)}, 400)
            except Exception as exc:
                self._send_json({"error": str(exc)}, 502)
            return
        if path == "/api/alerts":
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            rule_id = (query.get("rule_id") or [""])[0]
            if not self.monitor.can_access(user, rule_id):
                self._send_json({"error": "没有这个项目的权限"}, 403)
                return
            self._send_json(self.monitor.store.list_alerts(
                rule_id=rule_id,
                container=(query.get("container") or [""])[0],
                keyword=(query.get("keyword") or [""])[0],
            ))
            return
        if path == "/api/sources":
            if not user["is_admin"]:
                self._send_json({"error": "只有管理员可以管理日志源"}, 403)
                return
            self._send_json(self.monitor.store.list_sources())
            return
        if path == "/api/webhooks":
            self._send_json(self.monitor.store.list_webhooks())
            return
        if path == "/api/users":
            if not user["is_admin"]:
                self._send_json({"error": "只有管理员可以管理人员"}, 403)
                return
            self._send_json({"users": self.monitor.store.list_users(), "rules": self.monitor.snapshot(user)["rules"]})
            return
        self._send(404, "text/plain; charset=utf-8", b"not found")

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        try:
            if path == "/api/login":
                payload = self._read_json()
                token, user = self.monitor.login(str(payload.get("username", "")).strip(), str(payload.get("password", "")))
                self._send_json(user, extra_headers=[("Set-Cookie", f"vmlog_session={token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=604800")])
                return
            user = self._require_user()
            if not user:
                return
            if path == "/api/logout":
                self.monitor.logout(self._session_token())
                self._send_json({"ok": True}, extra_headers=[("Set-Cookie", "vmlog_session=; HttpOnly; Path=/; Max-Age=0")])
                return
            if path == "/api/me/password":
                payload = self._read_json()
                old_password = str(payload.get("old_password", ""))
                new_password = str(payload.get("new_password", ""))
                if not self.monitor.store.authenticate(user["username"], old_password):
                    raise ValueError("原密码不正确")
                if len(new_password) < 6:
                    raise ValueError("新密码至少 6 位")
                self.monitor.store.set_password(user["id"], new_password)
                self.monitor.store.audit(user["display_name"], "修改自己的密码", "", user["username"])
                self._send_json({"ok": True})
                return
            if path == "/api/rules":
                if not user["is_admin"]:
                    raise ValueError("只有管理员可以新建项目")
                self._send_json(self.monitor.upsert(self._read_json(), user=user))
                return
            if path.startswith("/api/rules/") and path.endswith("/members"):
                if not user["is_admin"]:
                    raise ValueError("只有管理员可以授权")
                rule_id = path[len("/api/rules/"):-len("/members")]
                self._require_rule(user, rule_id)
                payload = self._read_json()
                user_ids = payload.get("user_ids") or []
                self.monitor.store.set_rule_members(rule_id, user_ids)
                self.monitor.store.audit(user["display_name"], "项目授权", rule_id, ",".join(user_ids))
                self._send_json({"ok": True})
                return
            if path.startswith("/api/rules/") and path.endswith("/pause"):
                rule_id = path[len("/api/rules/"):-len("/pause")]
                self._require_rule(user, rule_id)
                paused = bool(self._read_json().get("paused"))
                self._send_json(self.monitor.set_paused(rule_id, paused, user))
                return
            if path == "/api/test":
                payload = self._read_json()
                self.monitor.send_feishu("【日志监控】这是一条测试消息。页面和飞书群已经连通。", payload.get("webhook"))
                self._send_json({"ok": True})
                return
            if path == "/api/webhooks":
                if not user["is_admin"]:
                    raise ValueError("只有管理员可以管理告警")
                item = self._webhook_from(self._read_json())
                self.monitor.store.save_webhook(item)
                self.monitor.rules = self.monitor.store.list_rules()
                self._restart_rules_for_webhook(item["id"])
                self.monitor.store.audit(user["display_name"], "保存Webhook", "", item["name"])
                self._send_json(item)
                return
            if path == "/api/sources":
                if not user["is_admin"]:
                    raise ValueError("只有管理员可以管理日志源")
                payload = self._read_json()
                source = self._source_from(payload)
                self.monitor.store.save_source(source)
                self.monitor.rules = self.monitor.store.list_rules()
                self.monitor.store.audit(user["display_name"], "保存日志源", "", source["name"])
                self._send_json(source)
                return
            if path == "/api/users":
                if not user["is_admin"]:
                    raise ValueError("只有管理员可以管理人员")
                payload = self._read_json()
                username = str(payload.get("username", "")).strip()
                password = str(payload.get("password", ""))
                if not username or not password:
                    raise ValueError("登录名和密码都要填写")
                user_id = self.monitor.store.create_user(
                    username,
                    str(payload.get("display_name", "")).strip() or username,
                    password,
                    bool(payload.get("is_admin")),
                    payload.get("rule_ids") or [],
                )
                self.monitor.store.audit(user["display_name"], "新建账号", "", username)
                self._send_json({"id": user_id})
                return
            if path.startswith("/api/users/") and path.endswith("/password"):
                if not user["is_admin"]:
                    raise ValueError("只有管理员可以修改密码")
                user_id = path[len("/api/users/"):-len("/password")]
                password = str(self._read_json().get("password", ""))
                if len(password) < 6:
                    raise ValueError("密码至少 6 位")
                self.monitor.store.set_password(user_id, password)
                self.monitor.store.audit(user["display_name"], "重置密码", "", user_id)
                self._send_json({"ok": True})
                return
            self._send(404, "text/plain; charset=utf-8", b"not found")
        except ValueError as exc:
            self._send_json({"error": str(exc)}, 400)
        except Exception as exc:
            self._send_json({"error": str(exc)}, 502)

    def do_PUT(self):
        path = urllib.parse.urlparse(self.path).path
        user = self._require_user()
        if not user:
            return
        try:
            if path.startswith("/api/webhooks/"):
                if not user["is_admin"]:
                    raise ValueError("只有管理员可以管理告警")
                item = self._webhook_from(self._read_json(), path[len("/api/webhooks/"):])
                self.monitor.store.save_webhook(item)
                self.monitor.rules = self.monitor.store.list_rules()
                self._restart_rules_for_webhook(item["id"])
                self._send_json(item)
                return
            if path.startswith("/api/sources/"):
                if not user["is_admin"]:
                    raise ValueError("只有管理员可以管理日志源")
                source = self._source_from(self._read_json(), path[len("/api/sources/"):])
                self.monitor.store.save_source(source)
                self.monitor.rules = self.monitor.store.list_rules()
                for rule in list(self.monitor.rules):
                    if rule.get("source_id") == source["id"] and should_watch(rule):
                        self.monitor._restart_worker(rule)
                self._send_json(source)
                return
            if path.startswith("/api/users/"):
                if not user["is_admin"]:
                    raise ValueError("只有管理员可以管理人员")
                user_id = path[len("/api/users/"):]
                payload = self._read_json()
                self.monitor.store.update_user(
                    user_id,
                    str(payload.get("display_name", "")).strip() or "未命名",
                    bool(payload.get("is_admin")),
                    bool(payload.get("enabled", True)),
                    payload.get("rule_ids") or [],
                )
                self.monitor.store.audit(user["display_name"], "修改账号", "", user_id)
                self._send_json({"ok": True})
                return
            prefix = "/api/rules/"
            if not path.startswith(prefix):
                self._send(404, "text/plain; charset=utf-8", b"not found")
                return
            rule_id = path[len(prefix):]
            self._require_rule(user, rule_id)
            self._send_json(self.monitor.upsert(self._read_json(), rule_id, user))
        except ValueError as exc:
            self._send_json({"error": str(exc)}, 400)
        except Exception as exc:
            self._send_json({"error": str(exc)}, 502)

    def do_DELETE(self):
        path = urllib.parse.urlparse(self.path).path
        user = self._require_user()
        if not user:
            return
        if path.startswith("/api/webhooks/"):
            if not user["is_admin"]:
                self._send_json({"error": "只有管理员可以管理告警"}, 403)
                return
            try:
                self.monitor.store.delete_webhook(path[len("/api/webhooks/"):])
                self._send_json({"ok": True})
            except ValueError as exc:
                self._send_json({"error": str(exc)}, 400)
            return
        if path.startswith("/api/sources/"):
            if not user["is_admin"]:
                self._send_json({"error": "只有管理员可以管理日志源"}, 403)
                return
            try:
                self.monitor.store.delete_source(path[len("/api/sources/"):])
                self._send_json({"ok": True})
            except ValueError as exc:
                self._send_json({"error": str(exc)}, 400)
            return
        if path.startswith("/api/users/"):
            if not user["is_admin"]:
                self._send_json({"error": "只有管理员可以删除用户"}, 403)
                return
            user_id = path[len("/api/users/"):]
            if user_id == user["id"]:
                self._send_json({"error": "不能删除当前登录账号"}, 400)
                return
            try:
                self.monitor.store.delete_user(user_id)
                self.monitor.store.audit(user["display_name"], "删除用户", "", user_id)
                self._send_json({"ok": True})
            except ValueError as exc:
                self._send_json({"error": str(exc)}, 400)
            return
        prefix = "/api/rules/"
        if not path.startswith(prefix):
            self._send(404, "text/plain; charset=utf-8", b"not found")
            return
        if not user["is_admin"]:
            self._send_json({"error": "只有管理员可以删除项目"}, 403)
            return
        self.monitor.delete(path[len(prefix):], user)
        self._send_json({"ok": True})



    def _webhook_from(self, payload, webhook_id=None):
        name = str(payload.get("name", "")).strip()
        url = str(payload.get("url", "")).strip()
        if not name or not url.startswith("http"):
            raise ValueError("名称和 Webhook 地址都要填写")
        return {"id": webhook_id or str(int(time.time() * 1000)), "name": name[:80], "url": url[:300]}

    def _restart_rules_for_webhook(self, webhook_id):
        for rule in list(self.monitor.rules):
            if rule.get("webhook_id") == webhook_id and should_watch(rule):
                self.monitor._restart_worker(rule)

    def _source_from(self, payload, source_id=None):
        name = str(payload.get("name", "")).strip()
        url = str(payload.get("url", "")).strip().rstrip("/")
        if not name or not url:
            raise ValueError("名称和地址都要填写")
        return {
            "id": source_id or str(int(time.time() * 1000)),
            "name": name[:80],
            "url": url[:300],
            "account_id": str(payload.get("account_id", "1")).strip() or "1",
            "project_id": str(payload.get("project_id", "1")).strip() or "1",
        }

    def _require_rule(self, user, rule_id):
        if not self.monitor.can_access(user, rule_id):
            raise ValueError("没有这个项目的权限")

    def _session_token(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            part = part.strip()
            if part.startswith("vmlog_session="):
                return part.split("=", 1)[1]
        return ""

    def _require_user(self):
        user = self.monitor.session_user(self._session_token())
        if not user:
            self._send_json({"error": "请先登录"}, 401)
            return None
        return user

    def _read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw.decode("utf-8") or "{}")

    def _send_json(self, payload, status=200, extra_headers=None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for key, value in extra_headers or []:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _send(self, status, content_type, body):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


def main():
    config = load_config()
    if not config["mysql"].get("user"):
        raise SystemExit("请先在 config.yaml 里填写 MySQL 账号")
    monitor = Monitor(config)
    auth = config.get("auth", {})
    logs = config.get("victorialogs", {})
    monitor.store.ensure_default_source(logs.get("url", ""), logs.get("account_id", "1"), logs.get("project_id", "1"))
    monitor.rules = monitor.store.list_rules()
    generated = monitor.store.ensure_admin(auth.get("admin_user") or "admin", auth.get("admin_password") or "")
    if generated:
        print(f"初始管理员：{auth.get('admin_user') or 'admin'}", flush=True)
        print(f"初始密码：{generated}", flush=True)
        print("请登录后尽快修改密码。", flush=True)
    monitor.start()
    Handler.monitor = monitor
    host = config["server"].get("host", "127.0.0.1")
    port = int(config["server"].get("port", "8787"))
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"日志监控已启动: http://{host}:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
