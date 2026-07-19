# 小城笺备份系统

> 详见 [ADR 0072](../../docs/adr/0072-mvp-backup-simplified.md) · MVP 备份简化方案

## ⚠️ 实施路径说明(2026-07-19 P1.1d 部署)

ADR 0072 原决策路径 `/etc/xcj-backup.key` + `/opt/xcj-backups/`,实际部署调整为 xcj-claude home 下:

| 项 | ADR 0072 原决策 | 实际部署(xcj-claude) | 原因 |
|---|---|---|---|
| 密钥 | `/etc/xcj-backup.key` | `~/.config/xcj-backup.key` | sudo 白名单无 mkdir,xcj-claude 无法创建 /etc/ 下文件 |
| 配置 | `/etc/xcj-backup.env` | `~/.config/xcj-backup.env` | 同上 |
| 备份目录 | `/opt/xcj-backups/` | `~/backups/` | 同上 |
| 日志 | `/var/log/xcj-backup.log` | `~/backups/backup.log` | xcj-claude 无 /var/log/ 写权限 |
| crontab | root 用户 | xcj-claude 用户自己的 | xcj-claude 无 root crontab 权限 |
| 脚本位置 | `/opt/xiaochengjian/deploy/backup/`(入库) | `~/scripts/`(部署副本,scp 传入) | /opt/xiaochengjian 是 root 所有,xcj-claude 无写权限 |

**入库脚本**(`deploy/backup/`)保持 `/etc/` 和 `/opt/` 默认(通用,任何部署都能用),通过 `XCJ_BACKUP_ENV` 和 `XCJ_BACKUP_LOG` 环境变量覆盖指向实际路径。

**决策不变**:本地 + 7 天 + gpg AES-256(只是路径实施调整,非架构决策变更)。

## 方案概览

| 项 | 方案 |
|---|---|
| 频率 | 每日凌晨 3:00 CST 全量 pg_dump |
| 存储 | 服务器本地 `~/backups/`(xcj-claude home) |
| 加密 | gpg AES-256 对称加密 |
| 保留 | 7 天滚动(7 份) |
| RPO | 24h |
| RTO | 30min(手动 restore.sh) |

## 文件清单

| 文件 | 用途 | 入库 |
|---|---|---|
| `backup.sh` | 备份脚本(pg_dump + gpg 加密 + 7 天清理) | ✅ |
| `restore.sh` | 恢复脚本(解密 + 停 backend + pg_restore + 启 backend + health 验证) | ✅ |
| `restore-test.sh` | 恢复演练脚本(恢复到临时库,验证表数量,不影响生产) | ✅ |
| `backup.env.example` | 配置模板 | ✅ |
| `README.md` | 本文档 | ✅ |
| `/etc/xcj-backup.env` | 实际配置(含容器名/路径) | ❌ 服务器本地 |
| `/etc/xcj-backup.key` | gpg 密钥(32+ 字符随机串) | ❌ 服务器本地 |

## 部署步骤

### 1. 入库脚本到服务器(随项目部署)

脚本已入库,`git pull` 后位于 `/opt/xiaochengjian/deploy/backup/`。

### 2. 创建 gpg 密钥

```bash
# 生成 32 字符随机密钥
openssl rand -base64 32 > /etc/xcj-backup.key
chmod 600 /etc/xcj-backup.key
chown root:root /etc/xcj-backup.key

# 验证权限
ls -l /etc/xcj-backup.key
# 应显示: -rw------- root root
```

**⚠️ 密钥备份**:把 `/etc/xcj-backup.key` 复制一份到管理员本地(USB / 密码管理器),服务器挂了密钥也丢则备份不可用。

### 3. 创建配置文件

```bash
cp /opt/xiaochengjian/deploy/backup/backup.env.example /etc/xcj-backup.env
chmod 600 /etc/xcj-backup.env
chown root:root /etc/xcj-backup.env

# 编辑配置(按实际环境调整)
nano /etc/xcj-backup.env
```

关键配置项:
- `BACKUP_DIR`:默认 `/opt/xcj-backups`,需保证磁盘空间(每份约 10-50MB,7 份约 350MB)
- `PG_CONTAINER`:默认 `xcj-postgres`,与 docker-compose.yml 一致
- `PG_USER` / `PG_DB`:与 `.env` 的 `POSTGRES_USER` / `POSTGRES_DB` 一致
- `HEALTH_URL`:宿主机访问 backend 的 URL(默认 `http://localhost:8088/health`,走 xcj-nginx 反代)
- `KEY_FILE`:默认 `/etc/xcj-backup.key`

### 4. 创建备份目录

```bash
mkdir -p /opt/xcj-backups
chmod 700 /opt/xcj-backups
chown root:root /opt/xcj-backups
```

### 5. 赋予脚本执行权限

```bash
chmod +x /opt/xiaochengjian/deploy/backup/*.sh
```

### 6. 手动跑一次备份验证

```bash
/opt/xiaochengjian/deploy/backup/backup.sh
```

预期输出:
```
=== 小城笺备份开始 2026-07-19-030000 ===
[1/4] PostgreSQL 全量备份...
  pg_dump 完成: 12M
[2/4] gpg AES-256 加密...
  加密完成: 12M
[3/4] schema.prisma + .env 备份...
  schema 备份: /opt/xcj-backups/schema/schema-2026-07-19.tar.gz
  .env 备份(脱敏): /opt/xcj-backups/env/env-2026-07-19.tar.gz
[4/4] 清理 7 天前备份...
  清理 0 个过期文件
=== 备份完成 ===
```

### 7. 跑一次恢复演练(不影响生产)

```bash
/opt/xiaochengjian/deploy/backup/restore-test.sh /opt/xcj-backups/pg/xcj-*.dump.gpg
```

预期输出含:
```
[4/5] 验证数据完整性...
  表数量: 12
  关键表记录数:
    Developer: 1 条
    Application: 2 条
    ...
=== 恢复演练完成 ===
```

### 8. 配置 crontab 自动备份

```bash
crontab -e
```

添加一行:
```
0 3 * * * /opt/xiaochengjian/deploy/backup/backup.sh >> /var/log/xcj-backup.log 2>&1
```

### 9. 验证 crontab

```bash
crontab -l
# 应显示上面那行

# 查看下次执行时间
systemctl status cron
```

## 恢复流程(生产故障时)

### 步骤

```bash
# 1. 列出可用备份
ls -lh /opt/xcj-backups/pg/

# 2. 恢复(会停 backend 1-5 分钟)
/opt/xiaochengjian/deploy/backup/restore.sh /opt/xcj-backups/pg/xcj-2026-07-19-030000.dump.gpg

# 3. 手动验证关键业务
# - 登录 admin-web
# - 查看卡密列表
# - 用测试卡密激活验证
```

### 注意事项

- `restore.sh` 会用 `--clean --if-exists` **覆盖**当前数据库
- 恢复期间 backend 不可用(约 1-5 分钟)
- 恢复后数据回到备份时间点(凌晨 3:00),期间的新数据丢失
- **建议先跑 `restore-test.sh` 验证备份完整性,再跑 `restore.sh`**

## 日常运维

### 检查备份状态

```bash
# 查看备份列表
ls -lh /opt/xcj-backups/pg/

# 查看备份日志
tail -50 /var/log/xcj-backup.log

# 查看备份总占用
du -sh /opt/xcj-backups/
```

### 每季度恢复演练(ADR 0033 要求)

```bash
# 用最新备份跑恢复演练
LATEST=$(ls -t /opt/xcj-backups/pg/*.gpg | head -1)
/opt/xiaochengjian/deploy/backup/restore-test.sh "$LATEST"
```

记录演练结果(表数量 + 记录数 + 恢复时间),验证 RTO < 30min。

### 密钥轮换(建议每年)

```bash
# 1. 生成新密钥
openssl rand -base64 32 > /etc/xcj-backup.key.new
chmod 600 /etc/xcj-backup.key.new

# 2. 用新密钥重新加密现有备份(可选,旧密钥仍可用)
# 或直接用新密钥跑下一次备份,旧备份到期后自动清理

# 3. 替换密钥
mv /etc/xcj-backup.key.new /etc/xcj-backup.key

# 4. 更新管理员本地密钥副本
```

## 故障排查

### backup.sh 失败

| 错误 | 原因 | 解决 |
|---|---|---|
| `配置文件 /etc/xcj-backup.env 不存在` | 未部署配置 | 按"部署步骤 3"创建 |
| `$KEY_FILE 权限不是 600` | 密钥权限错误 | `chmod 600 /etc/xcj-backup.key` |
| `pg_dump 失败` | PG 容器未运行或凭证错 | `docker ps \| grep xcj-postgres` 检查 |
| `gpg 加密失败` | 密钥文件为空或权限错 | 检查 `/etc/xcj-backup.key` 内容 + 权限 |

### restore.sh 失败

| 错误 | 原因 | 解决 |
|---|---|---|
| `gpg 解密失败` | 密钥错误或文件损坏 | 用 `restore-test.sh` 验证备份完整性 |
| `pg_restore 有错误` | 部分对象不存在(通常可忽略) | 检查 tail 输出,若关键表缺失则恢复失败 |
| `health 检查超时` | backend 启动失败 | `docker logs xcj-backend` 排查 |

## 升级路径(ADR 0072 分阶段)

| 阶段 | 增量 | 触发条件 |
|---|---|---|
| MVP(当前) | 本地 + 7 天 + gpg | 立即实施 |
| v1.1 | + 月末备份 | 用户数 > 50 |
| v1.2 | + 异地备份(对象存储) | 用户数 > 200 |
| v2 | + WAL 流复制(RPO 5min) | 用户数 > 1000,升级 2C4G |
| v3 | + KMS 密钥管理 | 企业资质就绪 |

## 关联

- ADR 0072 · MVP 备份简化方案
- ADR 0033 · 数据备份与灾备(理想方案,分阶段落地)
- `deploy/docker-compose.yml`(PG 容器配置)
- `deploy/.env.example`(PG 用户/密码,实际值在服务器 `.env`)
