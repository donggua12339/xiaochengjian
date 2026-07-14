import { ApiProperty } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import { IsInt, IsOptional, IsString, Max, Min } from 'class-validator';

/**
 * 通用分页查询 DTO
 * 所有列表接口的分页参数继承此类
 */
export class PaginationDto {
  @ApiProperty({ description: '页码,从 1 开始', minimum: 1, default: 1, required: false })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  page?: number = 1;

  @ApiProperty({
    description: '每页数量',
    minimum: 1,
    maximum: 100,
    default: 20,
    required: false,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100)
  pageSize?: number = 20;

  @ApiProperty({ description: '排序字段', required: false })
  @IsOptional()
  @IsString()
  sortBy?: string;

  @ApiProperty({
    description: '排序方向',
    enum: ['asc', 'desc'],
    default: 'desc',
    required: false,
  })
  @IsOptional()
  @IsString()
  sortOrder?: 'asc' | 'desc' = 'desc';
}

/**
 * 分页响应 DTO
 */
export class PaginatedResponseDto<T> {
  @ApiProperty({ description: '数据列表' })
  items!: T[];

  @ApiProperty({ description: '总数' })
  total!: number;

  @ApiProperty({ description: '当前页码' })
  page!: number;

  @ApiProperty({ description: '每页数量' })
  pageSize!: number;

  @ApiProperty({ description: '总页数' })
  totalPages!: number;
}

/**
 * 构造分页响应
 */
export function paginate<T>(
  items: T[],
  total: number,
  page: number,
  pageSize: number,
): PaginatedResponseDto<T> {
  return {
    items,
    total,
    page,
    pageSize,
    totalPages: Math.ceil(total / pageSize) || 1,
  };
}
