import { Module } from '@nestjs/common';
import { InjectController } from './inject.controller';
import { InjectService } from './inject.service';

@Module({
  controllers: [InjectController],
  providers: [InjectService],
  exports: [InjectService],
})
export class InjectModule {}
