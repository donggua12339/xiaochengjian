import { Module } from '@nestjs/common';
import { SdkController } from './sdk.controller';
import { SdkService } from './sdk.service';
import { HandshakeService } from './handshake.service';
import { SdkSignatureGuard } from './signature.guard';

@Module({
  controllers: [SdkController],
  providers: [SdkService, HandshakeService, SdkSignatureGuard],
  exports: [SdkService, HandshakeService],
})
export class SdkModule {}
