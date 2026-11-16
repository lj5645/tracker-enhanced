# 部署资产

生产环境（Debian 13，单机）用到的 systemd 服务与调优脚本。

## 服务单元

| 文件 | 安装位置 | 说明 |
|---|---|---|
| `aquatic-tracker-http.service` | `/etc/systemd/system/` | HTTP tracker，`Restart=always`，日志 append 到 `/home/tracker/aquatic-http.log` |
| `aquatic-tracker-udp.service` | `/etc/systemd/system/` | UDP tracker，同上 |
| `tracker-tune.sh` | `/usr/local/sbin/` | 内核/网络调优（见 `docs/performance-tuning.md`） |

安装：

```bash
cp deploy/aquatic-tracker-*.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now aquatic-tracker-http.service aquatic-tracker-udp.service
```

日常运维：

```bash
systemctl status aquatic-tracker-http aquatic-tracker-udp   # 状态
systemctl restart aquatic-tracker-http                     # 重启单个协议
journalctl -u aquatic-tracker-http -n 50                   # 若未重定向日志
tail -f /home/tracker/aquatic-http.log                     # 实际日志位置
```

> **为什么用 systemd 而不是 `start.sh`/`stop.sh`**：裸 `nohup` 启动的进程在
> 服务器重启后不会自动恢复，也没有崩溃自愈（2026-11-16 曾因系统重启导致
> tracker 停摆 9 小时才发现）。systemd 单元提供开机自启、`Restart=always`
> 崩溃拉起、以及统一的日志/状态查看方式。
