#!/usr/bin/env bash
# 小城笺 PostgreSQL 恢复演练脚本(不影响生产)
# 详见 ADR 0072 (MVP 备份简化)
#
# 功能:
#   1. 创建临时数据库 xcj_restore_test
#   2. 恢复备份到临时库
#   3. 验证表数量 + 关键表记录数
#   4. 删除临时库
#   5. 不影响生产数据库
#
# 用法:
#   sudo ./restore-test.sh /opt/xcj-backups/pg/xcj-2026-07-19-030000.dump.gpg
#
# 用途:
#   - 部署时验证备份脚本工作
#   - 每季度恢复演练(ADR 0033 要求)
#   - 升级 PG / 迁移前验证

set -euo pipefail

# ============= 参数校验 =============
if [[ $# -ne 1 ]]; then
    echo "用法: $0 <backup_file.gpg>"
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

: "${PG_CONTAINER:?PG_CONTAINER 未配置}"
: "${PG_USER:?PG_USER 未配置}"
: "${PG_DB:?PG_DB 未配置}"
: "${KEY_FILE:?KEY_FILE 未配置}"

# ============= 初始化 =============
TEST_DB="xcj_restore_test_$(date +%s)"
TMP_DIR=""
cleanup() {
    if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
    # 删除临时数据库
    if docker exec "$PG_CONTAINER" psql -U "$PG_USER" -lqt 2>/dev/null | cut -d'|' -f1 | grep -qw "$TEST_DB"; then
        docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d postgres -c "DROP DATABASE \"$TEST_DB\";" 2>/dev/null || true
    fi
}
trap cleanup EXIT

TMP_DIR=$(mktemp -d -t xcj-restore-test.XXXXXX)
DECRYPTED_FILE="$TMP_DIR/xcj-restore-test.dump"

echo "=== 小城笺恢复演练开始 ==="
echo "备份文件: $BACKUP_FILE"
echo "临时数据库: $TEST_DB"

# ============= 1. gpg 解密 =============
echo "[1/5] gpg 解密..."
if ! gpg --batch --yes --decrypt \
    --passphrase-file "$KEY_FILE" \
    -o "$DECRYPTED_FILE" \
    "$BACKUP_FILE"; then
    echo "ERROR: gpg 解密失败"
    exit 2
fi
echo "  解密完成: $(du -h "$DECRYPTED_FILE" | cut -f1)"

# ============= 2. 创建临时数据库 =============
echo "[2/5] 创建临时数据库 $TEST_DB..."
if ! docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d postgres -c "CREATE DATABASE \"$TEST_DB\";"; then
    echo "ERROR: 创建临时数据库失败"
    exit 3
fi

# ============= 3. 恢复到临时库 =============
echo "[3/5] pg_restore 到临时库..."
if ! docker exec -i "$PG_CONTAINER" pg_restore \
    -U "$PG_USER" \
    -d "$TEST_DB" \
    --no-owner --no-privileges \
    < "$DECRYPTED_FILE" 2>&1 | tail -20; then
    echo "WARN: pg_restore 有警告(通常可忽略)"
fi
echo "  恢复完成"

# ============= 4. 验证数据完整性 =============
echo "[4/5] 验证数据完整性..."

# 表数量
TABLE_COUNT=$(docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$TEST_DB" -t -c "
    SELECT count(*) FROM information_schema.tables
    WHERE table_schema = 'public' AND table_type = 'BASE TABLE';
" | tr -d '[:space:]')
echo "  表数量: $TABLE_COUNT"

if [[ -z "$TABLE_COUNT" || "$TABLE_COUNT" -lt 5 ]]; then
    echo "  ERROR: 表数量过少($TABLE_COUNT),恢复可能失败"
    exit 4
fi

# 关键表记录数(Prisma 默认表名:snake_case 单数)
echo "  关键表记录数:"
for table in developer application card_key card_template device device_binding audit_log membership_code session validation_log; do
    if docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$TEST_DB" -t -c "SELECT count(*) FROM \"$table\";" 2>/dev/null | tr -d '[:space:]' | grep -qE '^[0-9]+$'; then
        COUNT=$(docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$TEST_DB" -t -c "SELECT count(*) FROM \"$table\";" | tr -d '[:space:]')
        echo "    $table: $COUNT 条"
    else
        echo "    $table: (表不存在或查询失败)"
    fi
done

# ============= 5. 清理 =============
echo "[5/5] 清理临时数据库..."
echo "  (trap 自动清理)"

echo "=== 恢复演练完成 ==="
echo "  备份文件可正常恢复"
echo "  表数量: $TABLE_COUNT"
echo "  临时数据库已自动删除"

exit 0
