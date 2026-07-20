-- Make appId nullable in audit_log_own (EULA_ACCEPT 记录不关联应用)
ALTER TABLE "audit_log_own" ALTER COLUMN "appId" DROP NOT NULL;

-- Drop foreign key constraint appId -> application(id)
ALTER TABLE "audit_log_own" DROP CONSTRAINT IF EXISTS "audit_log_own_appId_fkey";

-- Add index on hardener (梆梆自检查询用)
CREATE INDEX IF NOT EXISTS "audit_log_own_hardener_idx" ON "audit_log_own"("hardener");
