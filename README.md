# vmlog-monitor

按项目实时监控 VictoriaLogs。日志里出现关键字时，发送飞书告警。

## 准备

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp config.example.yaml config.yaml
```

在 `config.yaml` 里填写 VictoriaLogs 地址、MySQL 账号和飞书默认 Webhook。这个文件不会提交到仓库。

## 启动

```bash
.venv/bin/python app.py
```

第一次启动会创建管理员。如果没有在配置里写初始密码，终端会打印一次。

浏览器打开 `http://127.0.0.1:8791`。

## 检查

```bash
.venv/bin/python -m unittest tests.test_monitor -v
```
