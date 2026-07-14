-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'GENERATE_MEMBERSHIP_CODE';
ALTER TYPE "AuditAction" ADD VALUE 'REDEEM_MEMBERSHIP_CODE';

-- CreateTable
CREATE TABLE "membership_code" (
    "id" TEXT NOT NULL,
    "codeHash" TEXT NOT NULL,
    "codeSalt" TEXT NOT NULL,
    "codePrefix" TEXT NOT NULL,
    "level" "VipLevel" NOT NULL,
    "durationDays" INTEGER NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'UNUSED',
    "redeemedBy" TEXT,
    "redeemedAt" TIMESTAMP(3),
    "batchId" TEXT NOT NULL,
    "remark" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "membership_code_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "membership_code_codeHash_key" ON "membership_code"("codeHash");

-- CreateIndex
CREATE INDEX "membership_code_status_idx" ON "membership_code"("status");

-- CreateIndex
CREATE INDEX "membership_code_batchId_idx" ON "membership_code"("batchId");

-- CreateIndex
CREATE INDEX "membership_code_level_idx" ON "membership_code"("level");

-- AddForeignKey
ALTER TABLE "membership_code" ADD CONSTRAINT "membership_code_redeemedBy_fkey" FOREIGN KEY ("redeemedBy") REFERENCES "developer"("id") ON DELETE SET NULL ON UPDATE CASCADE;
