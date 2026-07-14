-- ===========================================
-- 小城笺 RLS(行级安全)策略
-- 详见 ADR 0018 (多租户隔离) 与 ADR 0006 (PostgreSQL)
--
-- 所有业务表按 "developerId" 隔离
-- 应用层通过 SET LOCAL app.tenant_id = 'uuid' 设置当前租户
-- RLS 自动过滤:只返回 "developerId" = 当前租户 的行
--
-- 注意:
--  - 列名用 "developerId"(camelCase,Prisma 默认)
--  - ENABLE RLS:启用行级安全
--  - FORCE RLS:对表 owner 也强制(默认 owner 绕过 RLS)
--  - current_setting('app.tenant_id', true):第二个参数 true 表示未设置时返回 NULL 而非报错
--  - 未设置 tenant_id 时,所有行被过滤(NULL = uuid 为 false)
-- ===========================================

-- 1. session 表(刷新令牌会话)
ALTER TABLE "session" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "session" FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON "session";
CREATE POLICY tenant_isolation ON "session"
  USING ("developerId" = current_setting('app.tenant_id', true));

-- 2. application 表(开发者应用)
ALTER TABLE "application" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "application" FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON "application";
CREATE POLICY tenant_isolation ON "application"
  USING ("developerId" = current_setting('app.tenant_id', true));

-- 3. card_template 表(卡密模板)
ALTER TABLE "card_template" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "card_template" FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON "card_template";
CREATE POLICY tenant_isolation ON "card_template"
  USING ("developerId" = current_setting('app.tenant_id', true));

-- 4. card_key 表(卡密)
ALTER TABLE "card_key" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "card_key" FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON "card_key";
CREATE POLICY tenant_isolation ON "card_key"
  USING ("developerId" = current_setting('app.tenant_id', true));

-- 5. device 表(设备指纹)
ALTER TABLE "device" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "device" FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON "device";
CREATE POLICY tenant_isolation ON "device"
  USING ("developerId" = current_setting('app.tenant_id', true));

-- 6. device_binding 表(卡密-设备绑定)
ALTER TABLE "device_binding" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "device_binding" FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON "device_binding";
CREATE POLICY tenant_isolation ON "device_binding"
  USING ("developerId" = current_setting('app.tenant_id', true));

-- 7. validation_log 表(验证日志)
ALTER TABLE "validation_log" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "validation_log" FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON "validation_log";
CREATE POLICY tenant_isolation ON "validation_log"
  USING ("developerId" = current_setting('app.tenant_id', true));

-- 8. audit_log 表(审计日志)
ALTER TABLE "audit_log" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "audit_log" FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON "audit_log";
CREATE POLICY tenant_isolation ON "audit_log"
  USING ("developerId" = current_setting('app.tenant_id', true));
