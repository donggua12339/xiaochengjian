import { Module } from '@nestjs/common';
import { CardKeyController } from './card-key.controller';
import { CardKeyService } from './card-key.service';

@Module({
  controllers: [CardKeyController],
  providers: [CardKeyService],
  exports: [CardKeyService],
})
export class CardKeyModule {}
