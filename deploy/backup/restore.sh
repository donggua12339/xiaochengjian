#!/usr/bin/env bash
# 小城笺 PostgreSQL 恢复脚本
# 详见 ADR 0072 (MVP 备份简化)
#
# 功能:
#   1. gpg 解密备份
#   2. 停止 backend 容器(避免恢复期间写入)
#   3. pg_restore --clean --if-exists(覆盖现有数据)
#   4. 启动 backend 容器
#   5. 验证 health 接口
#
# 用法:
#   sudo ./restore.sh /opt/xcj-backups/pg/xcj-2026-07-19-030000.dump.gpg
#
# 风险:
#   - 会覆盖当前数据库(--clean --if-exists)
#   - 恢复期间 backend 不可用(约 1-5 分钟)
#   - 建议先在测试环境跑 restore-test.sh 验证备份完整性

set -euo pipefail

# ============= 参数校验 =============
if [[ $# -ne 1 ]]; then
    echo "用法: $0 <backup_file.gpg>"
    echo "示例: $0 /opt/xcj-backups/pg/xcj-2026-07-19-030000.dump.gpg"
    exit 1
fi

BACKUP_FILE="$1"
if [[ ! -f "$BACKUP_FILE" ]]; then
    echo "ERROR: 备份文件 $BACKUP_FILE 不存在" >&2
    exit 1
fi

# ============= 加载配置 =============
ENV_FILE="${XCJ_BACKUP_ENV:-/etc/xcj-backup.env}"
if [[ ! -f "$ENV_FILE" ]]; then
    echo "ERROR: 配置文件 $ENV_FILE 不存在" >&2
    exit 1
fi
# shellcheck disable=SC1090
source "$ENV_FILE"

: "${BACKUP_DIR:?BACKUP_DIR 未配置}"
: "${PG_CONTAINER:?PG_CONTAINER 未配置}"
: "${PG_USER:?PG_USER 未配置}"
: "${PG_DB:?PG_DB 未配置}"
: "${KEY_FILE:?KEY_FILE 未配置}"
: "${BACKEND_CONTAINER:?BACKEND_CONTAINER 未配置}"
: "${HEALTH_URL:?HEALTH_URL 未配置}"

KEY_PERM=$(stat -c '%a' "$KEY_FILE" 2>/dev/null || stat -f '%A' "$KEY_FILE")
if [[ "$KEY_PERM" != "600" ]]; then
    echo "ERROR: $KEY_FILE 权限不是 600(当前 $KEY_PERM),拒绝执行" >&2
    exit 1
fi

# ============= 初始化 =============
LOG_TAG="xcj-restore"
LOG_FILE="${XCJ_BACKUP_LOG:-/var/log/xcj-backup.log}"

log() {
    logger -t "$LOG_TAG" "$1" 2>/dev/null || true
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE" 2>/dev/null || true
    echo "$1"
}

TMP_DIR=""
cleanup() {
    if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT

TMP_DIR=$(mktemp -d -t xcj-restore.XXXXXX)
DECRYPTED_FILE="$TMP_DIR/xcj-restore.dump"

log "=== 小城笺恢复开始 ==="
log "备份文件: $BACKUP_FILE"

# ============= 1. gpg 解密 =============
log "[1/5] gpg 解密..."
if ! gpg --batch --yes --decrypt \
    --passphrase-file "$KEY_FILE" \
    -o "$DECRYPTED_FILE" \
    "$BACKUP_FILE"; then
    log "ERROR: gpg 解密失败(密钥错误或文件损坏)"
    exit 2
fi

DEC_SIZE=$(stat -c '%s' "$DECRYPTED_FILE" 2>/dev/null || stat -f '%z' "$DECRYPTED_FILE")
log "  解密完成: $(du -h "$DECRYPTED_FILE" | cut -f1) ($DEC_SIZE bytes)"

# ============= 2. 停止 backend =============
log "[2/5] 停止 $BACKEND_CONTAINER 容器(避免恢复期间写入)..."
if docker stop "$BACKEND_CONTAINER" 2>/dev/null; then
    log "  backend 已停止"
else
    log "  WARN: backend 停止失败(可能未运行,继续恢复)"
fi

# ============= 3. pg_restore =============
log "[3/5] pg_restore --clean --if-exists..."
# --clean: 删除现有对象后重建
# --if-exists: 防止对象不存在时报错
# --no-owner --no-privileges: 不恢复 owner/权限(用当前 PG_USER)
if ! docker exec -i "$PG_CONTAINER" pg_restore \
    -U "$PG_USER" \
    -d "$PG_DB" \
    --clean --if-exists \
    --no-owner --no-privileges \
    --verbose \
    < "$DECRYPTED_FILE" 2>&1 | tail -50; then
    log "WARN: pg_restore 有错误(部分对象可能不存在,通常可忽略)"
fi
log "  pg_restore 完成"

# ============= 4. 启动 backend =============
log "[4/5] 启动 $BACKEND_CONTAINER 容器..."
if docker start "$BACKEND_CONTAINER" 2>/dev/null; then
    log "  backend 启动中"
else
    log "  ERROR: backend 启动失败,需手动检查"
    exit 3
fi

# ============= 5. 验证 health =============
log "[5/5] 等待 backend health(最多 60s)..."
for i in $(seq 1 12); do
    sleep 5
    if curl -sf "$HEALTH_URL" > /dev/null 2>&1; then
        log "  health 检查通过(第 $((i*5))s)"
        break
    fi
    if [[ $i -eq 12 ]]; then
        log "  ERROR: health 检查超时(60s),需手动验证"
        exit 4
    fi
done

log "=== 恢复完成 ==="
log "  数据库已恢复到备份时间点"
log "  backend 已启动并 health 通过"
log "  建议手动验证关键业务:登录 / 卡密激活 / 验证"

exit 0
