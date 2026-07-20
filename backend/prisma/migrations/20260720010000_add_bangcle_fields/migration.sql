-- AlterTable:为 audit_log_own 加梆梆加固自检字段(ADR 0078)
-- hardener: 加固厂商标识("bangcle" / null)
-- eulaVersion: EULA 版本号(仅 hardener=bangcle 时必填,锁 B)
-- eulaAccepted: EULA 接受状态(仅 hardener=bangcle 时必填,锁 B)

ALTER TABLE "audit_log_own" ADD COLUMN "hardener" TEXT;
ALTER TABLE "audit_log_own" ADD COLUMN "eulaVersion" TEXT;
ALTER TABLE "audit_log_own" ADD COLUMN "eulaAccepted" BOOLEAN;

-- CreateIndex:便于按加固厂商查询
CREATE INDEX "audit_log_own_hardener_idx" ON "audit_log_own"("hardener");
