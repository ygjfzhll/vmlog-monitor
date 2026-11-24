-- vmlog-monitor MySQL initialization
-- Creates the application database and all tables used by the service.

CREATE DATABASE IF NOT EXISTS vmlog_monitor
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_0900_ai_ci;

USE vmlog_monitor;

CREATE TABLE IF NOT EXISTS rules (
  id VARCHAR(32) NOT NULL,
  name VARCHAR(80) NOT NULL,
  namespace_name TEXT NOT NULL,
  containers TEXT NOT NULL,
  keywords TEXT NOT NULL,
  exclude_keywords TEXT NULL,
  tail_cursor_ms BIGINT NOT NULL DEFAULT 0,
  cooldown_sec INT NOT NULL,
  enabled TINYINT NOT NULL,
  webhook VARCHAR(300) NOT NULL DEFAULT '',
  webhook_id VARCHAR(32) NOT NULL DEFAULT '',
  matched_count BIGINT NOT NULL DEFAULT 0,
  paused TINYINT NOT NULL DEFAULT 0,
  source_id VARCHAR(32) NOT NULL DEFAULT '',
  deploy_mode VARCHAR(20) NOT NULL DEFAULT 'kubernetes',
  updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS tail_cursors (
  rule_id VARCHAR(32) NOT NULL,
  scope_key VARCHAR(80) NOT NULL,
  cursor_ms BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (rule_id, scope_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS alerts (
  id BIGINT NOT NULL AUTO_INCREMENT,
  created_at DATETIME NOT NULL,
  project VARCHAR(80) NOT NULL,
  keyword_text VARCHAR(80) NOT NULL,
  namespace_name VARCHAR(80) DEFAULT NULL,
  container_name VARCHAR(80) DEFAULT NULL,
  pod_name VARCHAR(160) DEFAULT NULL,
  log_time VARCHAR(40) DEFAULT NULL,
  message TEXT,
  delivered TINYINT NOT NULL,
  retry_count INT NOT NULL DEFAULT 0,
  error_text VARCHAR(300) DEFAULT NULL,
  body TEXT,
  rule_id VARCHAR(32) NOT NULL DEFAULT '',
  PRIMARY KEY (id),
  KEY idx_alerts_created (created_at),
  KEY idx_alerts_rule (rule_id, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS container_hits (
  rule_id VARCHAR(32) NOT NULL,
  container_name VARCHAR(120) NOT NULL,
  hit_count BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (rule_id, container_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS log_sources (
  id VARCHAR(32) NOT NULL,
  name VARCHAR(80) NOT NULL,
  base_url VARCHAR(300) NOT NULL,
  account_id VARCHAR(20) NOT NULL DEFAULT '1',
  project_id VARCHAR(20) NOT NULL DEFAULT '1',
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS webhooks (
  id VARCHAR(32) NOT NULL,
  name VARCHAR(80) NOT NULL,
  hook_url VARCHAR(300) NOT NULL,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS users (
  id VARCHAR(32) NOT NULL,
  username VARCHAR(40) NOT NULL,
  display_name VARCHAR(40) NOT NULL,
  password_hash VARCHAR(200) NOT NULL,
  is_admin TINYINT NOT NULL DEFAULT 0,
  enabled TINYINT NOT NULL DEFAULT 1,
  created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS project_members (
  user_id VARCHAR(32) NOT NULL,
  rule_id VARCHAR(32) NOT NULL,
  PRIMARY KEY (user_id, rule_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGINT NOT NULL AUTO_INCREMENT,
  created_at DATETIME NOT NULL,
  user_name VARCHAR(40) NOT NULL,
  action_name VARCHAR(40) NOT NULL,
  rule_id VARCHAR(32) NOT NULL DEFAULT '',
  detail VARCHAR(300) NOT NULL DEFAULT '',
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS settings (
  name VARCHAR(40) NOT NULL,
  value TEXT NOT NULL,
  PRIMARY KEY (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
