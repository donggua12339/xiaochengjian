#!/usr/bin/env bash
# 小城笺 PostgreSQL 备份脚本
# 详见 ADR 0072 (MVP 备份简化)
#
# 功能:
#   1. pg_dump 全量备份(custom 格式,二进制压缩)
#   2. gpg AES-256 对称加密
#   3. 备份 schema.prisma + .env(脱敏)
#   4. 7 天滚动清理
#   5. 日志到 syslog + /var/log/xcj-backup.log
#
# 用法:
#   sudo ./backup.sh
#   或 crontab: 0 3 * * * /opt/xiaochengjian/deploy/backup/backup.sh
#
# 依赖:
#   - /etc/xcj-backup.env(配置,权限 600)
#   - /etc/xcj-backup.key(gpg 密钥,权限 600)
#   - docker(访问 xcj-postgres 容器)

set -euo pipefail

# ============= 加载配置 =============
ENV_FILE="${XCJ_BACKUP_ENV:-/etc/xcj-backup.env}"
if [[ ! -f "$ENV_FILE" ]]; then
    echo "ERROR: 配置文件 $ENV_FILE 不存在" >&2
    exit 1
fi
# shellcheck disable=SC1090
source "$ENV_FILE"

# 必填项校验
: "${BACKUP_DIR:?BACKUP_DIR 未配置}"
: "${PG_CONTAINER:?PG_CONTAINER 未配置}"
: "${PG_USER:?PG_USER 未配置}"
: "${PG_DB:?PG_DB 未配置}"
: "${KEY_FILE:?KEY_FILE 未配置}"
: "${DEPLOY_DIR:?DEPLOY_DIR 未配置}"
: "${BACKEND_DIR:?BACKEND_DIR 未配置}"

# 密钥文件权限校验(必须 600)
KEY_PERM=$(stat -c '%a' "$KEY_FILE" 2>/dev/null || stat -f '%A' "$KEY_FILE")
if [[ "$KEY_PERM" != "600" ]]; then
    echo "ERROR: $KEY_FILE 权限不是 600(当前 $KEY_PERM),拒绝执行" >&2
    exit 1
fi

# ============= 初始化 =============
TIMESTAMP=$(date +%Y-%m-%d-%H%M%S)
DATE=$(date +%Y-%m-%d)
LOG_TAG="xcj-backup"
LOG_FILE="${XCJ_BACKUP_LOG:-/var/log/xcj-backup.log}"

log() {
    logger -t "$LOG_TAG" "$1" 2>/dev/null || true
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE" 2>/dev/null || true
    echo "$1"
}

# 临时文件清理
TMP_DIR=""
cleanup() {
    if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT

TMP_DIR=$(mktemp -d -t xcj-backup.XXXXXX)

# 创建备份目录
mkdir -p "$BACKUP_DIR/pg" "$BACKUP_DIR/schema" "$BACKUP_DIR/env"

log "=== 小城笺备份开始 $TIMESTAMP ==="

# ============= 1. PostgreSQL 全量备份 =============
log "[1/4] PostgreSQL 全量备份..."
PG_DUMP_FILE="$TMP_DIR/xcj-$TIMESTAMP.dump"

if ! docker exec "$PG_CONTAINER" pg_dump -U "$PG_USER" -d "$PG_DB" --format=custom --no-owner --no-privileges > "$PG_DUMP_FILE"; then
    log "ERROR: pg_dump 失败"
    exit 2
fi

PG_SIZE=$(stat -c '%s' "$PG_DUMP_FILE" 2>/dev/null || stat -f '%z' "$PG_DUMP_FILE")
log "  pg_dump 完成: $(du -h "$PG_DUMP_FILE" | cut -f1) ($PG_SIZE bytes)"

# ============= 2. gpg AES-256 加密 =============
log "[2/4] gpg AES-256 加密..."
ENCRYPTED_FILE="$BACKUP_DIR/pg/xcj-$TIMESTAMP.dump.gpg"

if ! gpg --batch --yes --symmetric \
    --cipher-algo AES256 \
    --passphrase-file "$KEY_FILE" \
    -o "$ENCRYPTED_FILE" \
    "$PG_DUMP_FILE"; then
    log "ERROR: gpg 加密失败"
    exit 3
fi

ENC_SIZE=$(stat -c '%s' "$ENCRYPTED_FILE" 2>/dev/null || stat -f '%z' "$ENCRYPTED_FILE")
log "  加密完成: $(du -h "$ENCRYPTED_FILE" | cut -f1) ($ENC_SIZE bytes)"

# ============= 3. schema + .env 备份 =============
log "[3/4] schema.prisma + .env 备份..."

# schema.prisma
SCHEMA_TAR="$BACKUP_DIR/schema/schema-$DATE.tar.gz"
if [[ -f "$BACKEND_DIR/prisma/schema.prisma" ]]; then
    tar -czf "$SCHEMA_TAR" -C "$BACKEND_DIR" prisma/schema.prisma 2>/dev/null || log "  WARN: schema.prisma 备份失败(非致命)"
    log "  schema 备份: $SCHEMA_TAR"
fi

# .env(脱敏:移除含 PASSWORD/SECRET/KEY/TOKEN 的行)
ENV_TAR="$BACKUP_DIR/env/env-$DATE.tar.gz"
if [[ -f "$DEPLOY_DIR/.env" ]]; then
    SANITIZED_ENV="$TMP_DIR/.env.sanitized"
    grep -v -iE '(PASSWORD|SECRET|KEY|TOKEN|WEBHOOK)=' "$DEPLOY_DIR/.env" > "$SANITIZED_ENV" 2>/dev/null || cp "$DEPLOY_DIR/.env" "$SANITIZED_ENV"
    tar -czf "$ENV_TAR" -C "$TMP_DIR" .env.sanitized 2>/dev/null || log "  WARN: .env 备份失败(非致命)"
    log "  .env 备份(脱敏): $ENV_TAR"
fi

# ============= 4. 7 天滚动清理 =============
log "[4/4] 清理 7 天前备份..."
DELETED_COUNT=$(find "$BACKUP_DIR" -type f -name "*.gpg" -mtime +7 -print -delete | wc -l)
DELETED_COUNT=$((DELETED_COUNT + $(find "$BACKUP_DIR" -type f -name "*.tar.gz" -mtime +7 -print -delete 2>/dev/null | wc -l)))
log "  清理 $DELETED_COUNT 个过期文件"

# ============= 完成 =============
TOTAL_SIZE=$(du -sh "$BACKUP_DIR" | cut -f1)
BACKUP_COUNT=$(find "$BACKUP_DIR" -name "*.gpg" | wc -l)
log "=== 备份完成 ==="
log "  备份文件: $ENCRYPTED_FILE"
log "  总占用: $TOTAL_SIZE"
log "  当前备份份数: $BACKUP_COUNT"
log "  下次自动备份: 明日 03:00(crontab)"

exit 0
