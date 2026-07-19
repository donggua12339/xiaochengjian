# ADR 0072 · MVP 备份简化:本地 + 7 天滚动 + gpg AES-256

- 状态:accepted
- 日期:2026-07-19
- 决策者:小城笺项目
- 层次:运维

## 变更记录

- **2026-07-19 初始版本**:决策本地 + 7 天 + gpg AES-256,ADR 0033 分阶段落地
- **2026-07-19 P1.1d 部署实施**:路径调整为 xcj-claude home 下
  - 原因:xcj-claude 账号 sudo 白名单无 `mkdir`,无法创建 `/opt/xcj-backups/` 和 `/etc/xcj-backup.key`
  - 实施:BACKUP_DIR=`/home/xcj-claude/backups/`,KEY_FILE=`/home/xcj-claude/.config/xcj-backup.key`,ENV_FILE=`/home/xcj-claude/.config/xcj-backup.env`
  - 入库脚本(`deploy/backup/`)保持 `/etc/` 和 `/opt/` 默认(通用),通过 `XCJ_BACKUP_ENV` 环境变量覆盖指向实际路径
  - 决策不变:本地 + 7 天 + gpg AES-256(只是路径实施调整,非架构决策变更)
  - 实际 PG_USER 是 `xcj_dba`(handover.md 写的 `xcj_admin` 不准,文档不一致,待 P1 修正)

## 背景

ADR 0033 决策"数据备份与灾备",理想方案:

| 项 | ADR 0033 理想 |
|---|---|
| PG 备份频率 | 全量每日 1 次 + WAL 增量实时 |
| 备份存储 | 本地 + 异地(对象存储 OSS/COS) |
| 备份加密 | AES-256,密钥与数据库分离,KMS 管理 |
| 保留期 | 7 天滚动 + 4 周末备份 + 12 月末备份 |
| RPO | 5 分钟(WAL 流复制) |
| RTO | 30 分钟 |
| 灾备演练 | 每季度 1 次恢复演练 |

实际约束:

1. **服务器资源**:雨云 1C2G(ADR 0046),PG `shared_buffers=128MB`(ADR 0050 调优),无资源跑 WAL 流复制 + 异地同步
2. **无异地存储**:未配 OSS/COS,且海外服务器(ADR 0045)访问国内 OSS 延迟高
3. **无 KMS**:个人开发者无企业资质,云厂商 KMS 门槛高
4. **当前状态**:`deploy/backup/` 目录不存在,无任何备份脚本,handover.md P4 列为待办

ADR 0033 状态仍是 `accepted`,但实际从未实现,违反 CLAUDE.md 第 10 节。本 ADR 明确 MVP 简化方案,并将 ADR 0033 的理想方案标记为"分阶段落地"。

## 决策

### MVP 备份方案(本地 + 7 天滚动 + gpg AES-256)

| 项 | MVP 方案(本 ADR) | ADR 0033 理想 | 差距 |
|---|---|---|---|
| 频率 | 每日全量 pg_dump(凌晨 3:00) | 全量 + WAL 实时 | 无 WAL,丢数据窗口 24h |
| 存储 | 服务器本地 `/opt/xcj-backups/` | 本地 + 异地 OSS | 无异地,服务器挂即全丢 |
| 加密 | gpg AES-256,密钥 `/etc/xcj-backup.key`(权限 600) | AES-256 + KMS | 无 KMS,密钥本地 |
| 保留 | 7 天滚动(7 份) | 7 天 + 4 周末 + 12 月末 | 无月末/周末 |
| RPO | 24h | 5min | 大 |
| RTO | 30min(手动 restore.sh) | 30min | 一致 |
| 演练 | 部署时跑一次 + 每季度手动 | 每季度 | 一致 |

### 备份内容

- ✅ PostgreSQL 全量(`pg_dump --format=custom` 二进制压缩)
- ✅ Prisma schema 快照(`backend/prisma/schema.prisma` 备份到 `/opt/xcj-backups/schema/`)
- ✅ backend `.env`(脱敏后:移除密码字段,保留 key 名)
- ❌ Redis(可重建,不备份,ADR 0033 明确不备份)
- ❌ Loki 日志(短期数据,不备份,ADR 0033 明确不备份)
- ❌ 卡密明文(服务端不存明文,无需备份,ADR 0033 明确不备份)

### 备份文件命名

```
/opt/xcj-backups/
├── schema/
│   └── schema-2026-07-19.tar.gz
├── env/
│   └── env-2026-07-19.tar.gz
└── pg/
    └── xcj-2026-07-19-030000.dump.gpg
```

### 加密方案

- **算法**:gpg symmetric AES-256(`gpg --batch --yes --symmetric --cipher-algo AES256 --passphrase-file /etc/xcj-backup.key`)
- **密钥文件**:`/etc/xcj-backup.key`(权限 600,root only)
- **密钥管理**:密钥与备份分离(备份在 `/opt/xcj-backups/`,密钥在 `/etc/`),服务器挂了密钥也丢,但备份文件即使被泄露也无法解密
- **密钥备份**:管理员本地保存一份密钥副本(USB / 密码管理器),不入库不入服务器

### 7 天滚动清理

- 备份完成后,删除 7 天前的备份文件(`find /opt/xcj-backups -mtime +7 -delete`)
- 每份备份含日期后缀,易于识别

### 恢复流程

```
1. SSH 上服务器
2. cd /opt/xiaochengjian/deploy/backup
3. sudo ./restore.sh /opt/xcj-backups/pg/xcj-2026-07-19-030000.dump.gpg
4. 脚本执行:
   a. gpg 解密(用 /etc/xcj-backup.key)
   b. 停止 backend 容器(docker stop xcj-backend)
   c. 恢复 PG(docker exec -i xcj-postgres pg_restore --clean --if-exists)
   d. 启动 backend 容器(docker start xcj-backend)
   e. 验证 health 接口
```

### 恢复演练

- 部署时跑一次:用最新备份恢复到测试库,验证数据完整性
- 每季度手动跑一次(ADR 0033 要求,本 ADR 保留)
- 演练脚本:`deploy/backup/restore-test.sh`(恢复到临时数据库,验证后删除)

### ADR 0033 分阶段落地路径

| 阶段 | 增量 | 触发条件 |
|---|---|---|
| MVP(本 ADR) | 本地 + 7 天 + gpg | 立即实施(P1.1) |
| v1.1 | + 月末备份(12 份/年) | 用户数 > 50 |
| v1.2 | + 异地备份(对象存储) | 用户数 > 200 或出现首次数据丢失事件 |
| v2 | + WAL 流复制(RPO 5min) | 用户数 > 1000,升级到 2C4G 服务器 |
| v3 | + KMS 密钥管理 | 企业资质就绪 |

## 备选方案

| 方案 | 优点 | 缺点 | 不选原因 |
|---|---|---|---|
| A. 等 ADR 0033 完整实现再上线 | 理想 | 阻塞生产,无备份期间 DB 故障即丢全部数据 | 风险不可接受 |
| B. 仅 pg_dump 无加密 | 简单 | 备份泄露即卡密 hash 泄露 | 不安全 |
| C. 本地 + 7 天 + gpg(本方案) | 务实、立即生效 | 无异地、无 WAL | 合理(MVP) |
| D. 接 OSS 异地(立即上) | 异地 | 海外服务器访问 OSS 慢,且 OSS 费用 + 配置复杂 | 推迟到 v1.2 |
| E. WAL 流复制(立即上) | RPO 5min | 1C2G 资源不足,需升级服务器 | 推迟到 v2 |

## 影响

- **正面:**
  - ADR 0033 与代码事实对齐(CLAUDE.md 第 10 节合规)
  - 立即消除"DB 故障即丢全部卡密数据"的生产风险
  - 分阶段路径清晰,后续升级有依据
  - 备份脚本入库(`deploy/backup/`),密码走 `/etc/xcj-backup.key`,符合"密码不入库"原则
- **负面:**
  - RPO 24h,凌晨故障会丢前一天数据(可接受,卡密激活有日志可重建)
  - 无异地,服务器挂了备份也丢(需管理员本地保存密钥 + 定期手动拉取备份)
  - 无 WAL,无法做时间点恢复(只能恢复到凌晨 3:00 的状态)
- **风险:**
  - `/etc/xcj-backup.key` 丢失则所有备份不可用
  - 缓解:管理员本地保存密钥副本,定期更换
  - 服务器被入侵:攻击者拿到 root 即拿到密钥 + 备份
  - 缓解:密钥权限 600,backup 目录权限 700,定期审计
  - 7 天后备份被删:误删数据 8 天后无法恢复
  - 缓解:重要操作前手动备份一份到管理员本地

## 关联

- **部分推迟 ADR 0033**(不标 superseded,因 ADR 0033 的"异地/WAL/KMS/月末"是分阶段目标,本 ADR 是 MVP 起点):
  - ADR 0033 · 数据备份与灾备(MVP 部分由本 ADR 落地,其余分阶段)
- **关联 ADR:**
  - 0006(PostgreSQL)
  - 0031(SaaS 部署,单机阶段)
  - 0045(海外服务器,无异地存储原因之一)
  - 0046(雨云 1C2G,资源约束)
  - 0050(服务器内存调优,WAL 推迟原因)
- **关联代码:**
  - `deploy/backup/backup.sh`(备份脚本,入库无密码)
  - `deploy/backup/restore.sh`(恢复脚本)
  - `deploy/backup/restore-test.sh`(恢复演练脚本)
  - `deploy/backup/README.md`(部署说明)
  - 服务器本地:`/etc/xcj-backup.key`(密钥,不入库)+ `/etc/xcj-backup.env`(配置,不入库)
- **关联文档:** `docs/handover.md` P4 待办(本 ADR 落地后可勾掉)
