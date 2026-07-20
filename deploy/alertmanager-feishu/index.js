const express = require('express');
const axios = require('axios');

const app = express();
app.use(express.json({ limit: '10mb' }));

const PORT = process.env.PORT || 5000;
const FEISHU_WEBHOOK = process.env.FEISHU_WEBHOOK_URL || '';
const WECHAT_WEBHOOK = process.env.WECHAT_WEBHOOK_URL || '';

if (!FEISHU_WEBHOOK && !WECHAT_WEBHOOK) {
  console.warn('[WARN] FEISHU_WEBHOOK_URL 和 WECHAT_WEBHOOK_URL 均未设置,告警将只记录日志不转发');
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

/**
 * 把 AlertManager 告警转成企业微信 markdown 消息
 */
function toWechatMarkdown(payload) {
  const alerts = payload.alerts || [];
  const status = payload.status || 'firing';
  const title = status === 'resolved' ? '✅ 告警已恢复' : '🚨 告警触发';

  const alertLines = alerts.map(a => {
    const labels = a.labels || {};
    const annotations = a.annotations || {};
    const name = labels.alertname || 'Unknown';
    const severity = labels.severity || 'warning';
    const service = labels.service || '-';
    const summary = annotations.summary || '';
    const description = annotations.description || '';
    return `**${name}** [${severity}] (${service})\n> ${summary}\n> ${description}`;
  }).join('\n\n');

  return {
    msgtype: 'markdown',
    markdown: {
      content: `## ${title} (${alerts.length} 条)\n\n${alertLines || '无告警详情'}\n\n<font color="comment">小城笺监控 · ${new Date().toISOString()}</font>`,
    },
  };
}

app.post('/alert', async (req, res) => {
  try {
    const payload = req.body;
    console.log(`[INFO] 收到告警:status=${payload.status}, count=${(payload.alerts || []).length}`);

    let sent = false;

    // 飞书
    if (FEISHU_WEBHOOK) {
      try {
        const feishuCard = toFeishuCard(payload);
        const resp = await axios.post(FEISHU_WEBHOOK, feishuCard, { timeout: 10000 });
        if (resp.data.code !== 0 && resp.data.StatusCode !== 0) {
          console.error('[ERROR] 飞书返回错误:', JSON.stringify(resp.data));
        } else {
          console.log('[INFO] 飞书告警已发送');
          sent = true;
        }
      } catch (err) {
        console.error('[ERROR] 飞书发送失败:', err.message);
      }
    }

    // 企业微信
    if (WECHAT_WEBHOOK) {
      try {
        const wechatMsg = toWechatMarkdown(payload);
        const resp = await axios.post(WECHAT_WEBHOOK, wechatMsg, { timeout: 10000 });
        if (resp.data.errcode !== 0) {
          console.error('[ERROR] 企业微信返回错误:', JSON.stringify(resp.data));
        } else {
          console.log('[INFO] 企业微信告警已发送');
          sent = true;
        }
      } catch (err) {
        console.error('[ERROR] 企业微信发送失败:', err.message);
      }
    }

    if (!sent && !FEISHU_WEBHOOK && !WECHAT_WEBHOOK) {
      console.log('[WARN] 飞书和企业微信 webhook 均未配置,跳过转发');
      return res.json({ ok: true, skipped: true });
    }

    res.json({ ok: true, sent });
  } catch (err) {
    console.error('[ERROR] 告警处理失败:', err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.listen(PORT, () => {
  console.log(`[INFO] 小城笺告警中转服务启动,端口 ${PORT}`);
  console.log(`[INFO] 飞书 webhook: ${FEISHU_WEBHOOK ? '已配置' : '未配置'}`);
  console.log(`[INFO] 企业微信 webhook: ${WECHAT_WEBHOOK ? '已配置' : '未配置'}`);
});
