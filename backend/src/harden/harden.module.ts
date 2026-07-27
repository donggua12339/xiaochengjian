import { Module } from '@nestjs/common';
import { HardenController } from './harden.controller';
import { HardenService } from './harden.service';

@Module({
  controllers: [HardenController],
  providers: [HardenService],
  exports: [HardenService],
})
export class HardenModule {}
