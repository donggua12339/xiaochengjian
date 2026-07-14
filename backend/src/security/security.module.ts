import { Module } from '@nestjs/common';
import { SecurityCheckService } from './security-check.service';

@Module({
  providers: [SecurityCheckService],
  exports: [SecurityCheckService],
})
export class SecurityModule {}
