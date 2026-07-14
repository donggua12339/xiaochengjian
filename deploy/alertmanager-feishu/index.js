/**
 * 小城笺 AlertManager 飞书告警中转服务
 *
 * 详见 ADR 0032 (监控告警:飞书机器人)
 *
 * 流程:
 *  1. AlertManager 发送告警到 POST /alert
 *  2. 本服务把 AlertManager 格式转成飞书消息卡片格式
 *  3. 转发到飞书 incoming webhook
 *
 * 飞书消息格式:互动卡片(text + 标题 + 颜色)
 */

const express = require('express');
const axios = require('axios');

const app = express();
app.use(express.json({ limit: '10mb' }));

const PORT = process.env.PORT || 5000;
const FEISHU_WEBHOOK = process.env.FEISHU_WEBHOOK_URL || '';

if (!FEISHU_WEBHOOK) {
  console.warn('[WARN] FEISHU_WEBHOOK_URL 未设置,告警将只记录日志不转发');
}

/**
 * 把 AlertManager 告警转成飞书消息卡片
 */
function toFeishuCard(payload) {
  const alerts = payload.alerts || [];
  const status = payload.status || 'firing';
  const color = status === 'resolved' ? 'green' : 'red';
  const title = status === 'resolved' ? '✅ 告警已恢复' : '🚨 告警触发';

  const alertLines = alerts.map(a => {
    const labels = a.labels || {};
    const annotations = a.annotations || {};
    const name = labels.alertname || 'Unknown';
    const severity = labels.severity || 'warning';
    const service = labels.service || '-';
    const summary = annotations.summary || '';
    const description = annotations.description || '';
    return `**${name}** [${severity}] (${service})\n${summary}\n${description}`;
  }).join('\n\n');

  return {
    msg_type: 'interactive',
    card: {
      header: {
        template: color,
        title: { tag: 'plain_text', content: `${title} (${alerts.length} 条)` },
      },
      elements: [
        { tag: 'div', text: { tag: 'lark_md', content: alertLines || '无告警详情' } },
        { tag: 'note', elements: [{ tag: 'plain_text', content: `小城笺监控 · ${new Date().toISOString()}` }] },
      ],
    },
  };
}

app.post('/alert', async (req, res) => {
  try {
    const payload = req.body;
    console.log(`[INFO] 收到告警:status=${payload.status}, count=${(payload.alerts || []).length}`);

    if (!FEISHU_WEBHOOK) {
      console.log('[WARN] 飞书 webhook 未配置,跳过转发');
      return res.json({ ok: true, skipped: true });
    }

    const feishuCard = toFeishuCard(payload);
    const resp = await axios.post(FEISHU_WEBHOOK, feishuCard, { timeout: 10000 });

    if (resp.data.code !== 0 && resp.data.StatusCode !== 0) {
      console.error('[ERROR] 飞书返回错误:', JSON.stringify(resp.data));
    } else {
      console.log('[INFO] 飞书告警已发送');
    }

    res.json({ ok: true });
  } catch (err) {
    console.error('[ERROR] 告警处理失败:', err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.listen(PORT, () => {
  console.log(`[INFO] 小城笺飞书告警中转服务启动,端口 ${PORT}`);
  console.log(`[INFO] 飞书 webhook: ${FEISHU_WEBHOOK ? '已配置' : '未配置'}`);
});
