-- AlterEnum:为 AuditAction 加自有诊断相关操作(ADR 0077)
ALTER TYPE "AuditAction" ADD VALUE 'SELF_AUDIT_ANALYZE';
ALTER TYPE "AuditAction" ADD VALUE 'SELF_AUDIT_RESIGN';

-- CreateTable:自有 APK 诊断审计日志(ADR 0077 §4)
CREATE TABLE "audit_log_own" (
    "id" TEXT NOT NULL,
    "developerId" TEXT NOT NULL,
    "appId" TEXT NOT NULL,
    "apkHash" TEXT NOT NULL,
    "apkSize" INTEGER NOT NULL,
    "packageName" TEXT NOT NULL,
    "signatureHash" TEXT NOT NULL,
    "check1Passed" BOOLEAN NOT NULL,
    "check2Passed" BOOLEAN NOT NULL,
    "check3Passed" BOOLEAN NOT NULL,
    "status" TEXT NOT NULL,
    "rejectReason" TEXT,
    "reportPath" TEXT,
    "operation" TEXT NOT NULL,
    "resignFromHash" TEXT,
    "resignToHash" TEXT,
    "keystoreFingerprint" TEXT,
    "ip" TEXT NOT NULL,
    "userAgent" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "audit_log_own_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "audit_log_own_developerId_createdAt_idx" ON "audit_log_own"("developerId", "createdAt");
CREATE INDEX "audit_log_own_appId_createdAt_idx" ON "audit_log_own"("appId", "createdAt");
CREATE INDEX "audit_log_own_status_idx" ON "audit_log_own"("status");
CREATE INDEX "audit_log_own_operation_idx" ON "audit_log_own"("operation");

-- AddForeignKey
ALTER TABLE "audit_log_own" ADD CONSTRAINT "audit_log_own_developerId_fkey" FOREIGN KEY ("developerId") REFERENCES "developer"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "audit_log_own" ADD CONSTRAINT "audit_log_own_appId_fkey" FOREIGN KEY ("appId") REFERENCES "application"("id") ON DELETE CASCADE ON UPDATE CASCADE;
