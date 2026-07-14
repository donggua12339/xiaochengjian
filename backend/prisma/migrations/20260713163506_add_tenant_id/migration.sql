/*
  Warnings:

  - Added the required column `developerId` to the `card_key` table without a default value. This is not possible if the table is not empty.
  - Added the required column `developerId` to the `card_template` table without a default value. This is not possible if the table is not empty.
  - Added the required column `developerId` to the `device` table without a default value. This is not possible if the table is not empty.
  - Added the required column `developerId` to the `device_binding` table without a default value. This is not possible if the table is not empty.
  - Added the required column `developerId` to the `validation_log` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "card_key" ADD COLUMN     "developerId" TEXT NOT NULL;

-- AlterTable
ALTER TABLE "card_template" ADD COLUMN     "developerId" TEXT NOT NULL;

-- AlterTable
ALTER TABLE "device" ADD COLUMN     "developerId" TEXT NOT NULL;

-- AlterTable
ALTER TABLE "device_binding" ADD COLUMN     "developerId" TEXT NOT NULL;

-- AlterTable
ALTER TABLE "validation_log" ADD COLUMN     "developerId" TEXT NOT NULL;

-- CreateIndex
CREATE INDEX "card_key_developerId_idx" ON "card_key"("developerId");

-- CreateIndex
CREATE INDEX "card_template_developerId_idx" ON "card_template"("developerId");

-- CreateIndex
CREATE INDEX "device_developerId_idx" ON "device"("developerId");

-- CreateIndex
CREATE INDEX "device_binding_developerId_idx" ON "device_binding"("developerId");

-- CreateIndex
CREATE INDEX "validation_log_developerId_createdAt_idx" ON "validation_log"("developerId", "createdAt");

-- AddForeignKey
ALTER TABLE "card_template" ADD CONSTRAINT "card_template_developerId_fkey" FOREIGN KEY ("developerId") REFERENCES "developer"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "card_key" ADD CONSTRAINT "card_key_developerId_fkey" FOREIGN KEY ("developerId") REFERENCES "developer"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device" ADD CONSTRAINT "device_developerId_fkey" FOREIGN KEY ("developerId") REFERENCES "developer"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_binding" ADD CONSTRAINT "device_binding_developerId_fkey" FOREIGN KEY ("developerId") REFERENCES "developer"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "validation_log" ADD CONSTRAINT "validation_log_developerId_fkey" FOREIGN KEY ("developerId") REFERENCES "developer"("id") ON DELETE CASCADE ON UPDATE CASCADE;
