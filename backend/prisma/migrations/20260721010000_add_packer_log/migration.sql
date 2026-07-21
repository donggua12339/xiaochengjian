-- CreateTable:自有 APK SDK 封装审计日志(ADR 0081)
CREATE TABLE "packer_log" (
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
    "check4Passed" BOOLEAN NOT NULL,
    "check5Passed" BOOLEAN NOT NULL,
    "check6Passed" BOOLEAN NOT NULL,
    "check7Passed" BOOLEAN NOT NULL,
    "status" TEXT NOT NULL,
    "rejectReason" TEXT,
    "dexInjected" BOOLEAN NOT NULL,
    "multidexHandled" BOOLEAN NOT NULL,
    "injectedDexHash" TEXT,
    "resignedApkHash" TEXT,
    "keystoreFingerprint" TEXT,
    "ip" TEXT NOT NULL,
    "userAgent" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "packer_log_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "packer_log_developerId_createdAt_idx" ON "packer_log"("developerId", "createdAt");
CREATE INDEX "packer_log_appId_createdAt_idx" ON "packer_log"("appId", "createdAt");
CREATE INDEX "packer_log_status_idx" ON "packer_log"("status");

-- AddForeignKey
ALTER TABLE "packer_log" ADD CONSTRAINT "packer_log_developerId_fkey" FOREIGN KEY ("developerId") REFERENCES "developer"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "packer_log" ADD CONSTRAINT "packer_log_appId_fkey" FOREIGN KEY ("appId") REFERENCES "application"("id") ON DELETE CASCADE ON UPDATE CASCADE;
