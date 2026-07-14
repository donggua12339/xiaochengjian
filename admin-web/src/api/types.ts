export type CardKeyType = 'DAY' | 'WEEK' | 'MONTH' | 'PERMANENT' | 'TRIAL';
export type BindingStrategy = 'NONE' | 'FIRST_BIND' | 'N_DEVICES';

export const CARD_KEY_TYPE_LABELS: Record<CardKeyType, string> = {
  DAY: '日卡',
  WEEK: '周卡',
  MONTH: '月卡',
  PERMANENT: '永久卡',
  TRIAL: '试用卡',
};

export const BINDING_STRATEGY_LABELS: Record<BindingStrategy, string> = {
  NONE: '不绑定',
  FIRST_BIND: '首次激活绑定',
  N_DEVICES: '多设备(N 台)',
};

export const CARD_STATUS_LABELS: Record<string, string> = {
  ACTIVE: '活跃',
  DISABLED: '已禁用',
  EXPIRED: '已过期',
  USED_UP: '已用尽',
};
