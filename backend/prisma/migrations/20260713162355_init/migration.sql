-- CreateEnum
CREATE TYPE "DeveloperRole" AS ENUM ('DEVELOPER', 'ADMIN');

-- CreateEnum
CREATE TYPE "VipLevel" AS ENUM ('FREE', 'MONTHLY', 'LIFETIME', 'VIP');

-- CreateEnum
CREATE TYPE "CardKeyType" AS ENUM ('DAY', 'WEEK', 'MONTH', 'PERMANENT', 'TRIAL');

-- CreateEnum
CREATE TYPE "BindingStrategy" AS ENUM ('NONE', 'FIRST_BIND', 'N_DEVICES');

-- CreateEnum
CREATE TYPE "CardKeyStatus" AS ENUM ('ACTIVE', 'DISABLED', 'EXPIRED', 'USED_UP');

-- CreateEnum
CREATE TYPE "AuditAction" AS ENUM ('REGISTER', 'LOGIN', 'LOGOUT', 'CREATE_APP', 'UPDATE_APP', 'DELETE_APP', 'ROTATE_SECRET', 'GENERATE_CARDS', 'DISABLE_CARD', 'ENABLE_CARD', 'UNBIND_DEVICE', 'EXPORT_CARDS');

-- CreateTable
CREATE TABLE "developer" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "totpSecret" TEXT,
    "totpEnabled" BOOLEAN NOT NULL DEFAULT false,
    "backupCodes" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "role" "DeveloperRole" NOT NULL DEFAULT 'DEVELOPER',
    "vipLevel" "VipLevel" NOT NULL DEFAULT 'FREE',
    "vipExpiresAt" TIMESTAMP(3),
    "maxApps" INTEGER NOT NULL DEFAULT 5,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "lastLoginAt" TIMESTAMP(3),
    "lastLoginIp" TEXT,

    CONSTRAINT "developer_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "session" (
    "id" TEXT NOT NULL,
    "developerId" TEXT NOT NULL,
    "refreshTokenHash" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "userAgent" TEXT,
    "ip" TEXT,

    CONSTRAINT "session_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "application" (
    "id" TEXT NOT NULL,
    "developerId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "packageName" TEXT NOT NULL,
    "appSecretHash" TEXT NOT NULL,
    "signHashAllowList" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "rateLimitIpPerMinute" INTEGER,
    "rateLimitDevicePerMinute" INTEGER,
    "rateLimitFailLockThreshold" INTEGER,
    "rateLimitFailLockTtl" INTEGER,
    "offlineCacheDays" INTEGER NOT NULL DEFAULT 7,
    "sdkRsaPublicKeyHash" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "application_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "card_template" (
    "id" TEXT NOT NULL,
    "appId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "type" "CardKeyType" NOT NULL,
    "bindingStrategy" "BindingStrategy" NOT NULL,
    "maxDevices" INTEGER NOT NULL DEFAULT 1,
    "count" INTEGER NOT NULL DEFAULT 100,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "card_template_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "card_key" (
    "id" TEXT NOT NULL,
    "appId" TEXT NOT NULL,
    "cardKeyHash" TEXT NOT NULL,
    "cardSalt" TEXT NOT NULL,
    "type" "CardKeyType" NOT NULL,
    "bindingStrategy" "BindingStrategy" NOT NULL,
    "maxDevices" INTEGER NOT NULL DEFAULT 1,
    "status" "CardKeyStatus" NOT NULL DEFAULT 'ACTIVE',
    "activatedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3),
    "trialClaimedDeviceId" TEXT,
    "cardKeyPrefix" TEXT NOT NULL,
    "remark" TEXT,
    "batchId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "card_key_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "device" (
    "id" TEXT NOT NULL,
    "appId" TEXT NOT NULL,
    "machineId" TEXT NOT NULL,
    "fingerprintHash" TEXT NOT NULL,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "device_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "device_binding" (
    "id" TEXT NOT NULL,
    "cardKeyId" TEXT NOT NULL,
    "deviceId" TEXT NOT NULL,
    "appId" TEXT NOT NULL,
    "boundAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "device_binding_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "validation_log" (
    "id" TEXT NOT NULL,
    "appId" TEXT NOT NULL,
    "cardKeyHash" TEXT NOT NULL,
    "machineId" TEXT NOT NULL,
    "ip" TEXT NOT NULL,
    "userAgent" TEXT,
    "success" BOOLEAN NOT NULL,
    "failReason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "validation_log_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "audit_log" (
    "id" TEXT NOT NULL,
    "developerId" TEXT NOT NULL,
    "action" "AuditAction" NOT NULL,
    "target" TEXT,
    "ip" TEXT,
    "userAgent" TEXT,
    "meta" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "audit_log_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "developer_email_key" ON "developer"("email");

-- CreateIndex
CREATE UNIQUE INDEX "session_refreshTokenHash_key" ON "session"("refreshTokenHash");

-- CreateIndex
CREATE INDEX "session_developerId_idx" ON "session"("developerId");

-- CreateIndex
CREATE INDEX "application_developerId_idx" ON "application"("developerId");

-- CreateIndex
CREATE UNIQUE INDEX "application_developerId_packageName_key" ON "application"("developerId", "packageName");

-- CreateIndex
CREATE INDEX "card_template_appId_idx" ON "card_template"("appId");

-- CreateIndex
CREATE UNIQUE INDEX "card_key_cardKeyHash_key" ON "card_key"("cardKeyHash");

-- CreateIndex
CREATE INDEX "card_key_appId_status_idx" ON "card_key"("appId", "status");

-- CreateIndex
CREATE INDEX "card_key_appId_batchId_idx" ON "card_key"("appId", "batchId");

-- CreateIndex
CREATE INDEX "card_key_appId_type_idx" ON "card_key"("appId", "type");

-- CreateIndex
CREATE INDEX "card_key_trialClaimedDeviceId_idx" ON "card_key"("trialClaimedDeviceId");

-- CreateIndex
CREATE INDEX "device_appId_idx" ON "device"("appId");

-- CreateIndex
CREATE UNIQUE INDEX "device_appId_machineId_key" ON "device"("appId", "machineId");

-- CreateIndex
CREATE INDEX "device_binding_cardKeyId_idx" ON "device_binding"("cardKeyId");

-- CreateIndex
CREATE INDEX "device_binding_deviceId_idx" ON "device_binding"("deviceId");

-- CreateIndex
CREATE INDEX "device_binding_appId_idx" ON "device_binding"("appId");

-- CreateIndex
CREATE UNIQUE INDEX "device_binding_cardKeyId_deviceId_key" ON "device_binding"("cardKeyId", "deviceId");

-- CreateIndex
CREATE INDEX "validation_log_appId_createdAt_idx" ON "validation_log"("appId", "createdAt");

-- CreateIndex
CREATE INDEX "validation_log_appId_success_idx" ON "validation_log"("appId", "success");

-- CreateIndex
CREATE INDEX "validation_log_machineId_idx" ON "validation_log"("machineId");

-- CreateIndex
CREATE INDEX "audit_log_developerId_createdAt_idx" ON "audit_log"("developerId", "createdAt");

-- CreateIndex
CREATE INDEX "audit_log_action_idx" ON "audit_log"("action");

-- AddForeignKey
ALTER TABLE "session" ADD CONSTRAINT "session_developerId_fkey" FOREIGN KEY ("developerId") REFERENCES "developer"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "application" ADD CONSTRAINT "application_developerId_fkey" FOREIGN KEY ("developerId") REFERENCES "developer"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "card_template" ADD CONSTRAINT "card_template_appId_fkey" FOREIGN KEY ("appId") REFERENCES "application"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "card_key" ADD CONSTRAINT "card_key_appId_fkey" FOREIGN KEY ("appId") REFERENCES "application"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device" ADD CONSTRAINT "device_appId_fkey" FOREIGN KEY ("appId") REFERENCES "application"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_binding" ADD CONSTRAINT "device_binding_cardKeyId_fkey" FOREIGN KEY ("cardKeyId") REFERENCES "card_key"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_binding" ADD CONSTRAINT "device_binding_deviceId_fkey" FOREIGN KEY ("deviceId") REFERENCES "device"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "validation_log" ADD CONSTRAINT "validation_log_appId_fkey" FOREIGN KEY ("appId") REFERENCES "application"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "audit_log" ADD CONSTRAINT "audit_log_developerId_fkey" FOREIGN KEY ("developerId") REFERENCES "developer"("id") ON DELETE CASCADE ON UPDATE CASCADE;
