/**
 * 端到端加固流程测试脚本
 * 在 Docker 容器内运行: node /tmp/test-harden-flow.mjs
 */
import http from 'node:http';
import fs from 'node:fs';

const BASE = 'http://localhost:3000/v1';
const TOKEN = process.env.TEST_TOKEN || '';
const APK_PATH = '/tmp/test.apk';
const KS_PATH = '/tmp/test-ks.jks';
const KS_PASS = 'testpass123';
const KS_ALIAS = 'testkey';
const CHUNK_SIZE = 5 * 1024 * 1024; // 5MB

function req(method, path, body, contentType) {
  return new Promise((resolve, reject) => {
    const url = new URL(BASE + path);
    const headers = { 'Authorization': `Bearer ${TOKEN}` };
    let payload = null;
    if (body && contentType === 'json') {
      payload = JSON.stringify(body);
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(payload);
    } else if (body && typeof body === 'object' && body.boundary) {
      headers['Content-Type'] = `multipart/form-data; boundary=${body.boundary}`;
      payload = body.data;
      headers['Content-Length'] = payload.length;
    }
    const r = http.request({ hostname: url.hostname, port: url.port, path: url.pathname, method, headers }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, data }); }
      });
    });
    r.on('error', reject);
    if (payload) r.write(payload);
    r.end();
  });
}

function buildMultipart(fields) {
  const boundary = '----TestBoundary' + Date.now();
  const parts = [];
  for (const [name, value] of Object.entries(fields)) {
    if (value instanceof Buffer) {
      parts.push(`--${boundary}\r\nContent-Disposition: form-data; name="${name}"; filename="chunk"\r\nContent-Type: application/octet-stream\r\n\r\n`);
      parts.push(value);
      parts.push('\r\n');
    } else {
      parts.push(`--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`);
    }
  }
  parts.push(`--${boundary}--\r\n`);
  const buffers = parts.map(p => typeof p === 'string' ? Buffer.from(p) : p);
  return { boundary, data: Buffer.concat(buffers) };
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function main() {
  const apkBuf = fs.readFileSync(APK_PATH);
  const totalChunks = Math.ceil(apkBuf.length / CHUNK_SIZE);
  console.log(`APK: ${apkBuf.length} bytes, ${totalChunks} chunks`);

  // Step 1: Init
  console.log('\n=== Step 1: upload/init ===');
  const initRes = await req('POST', '/hardening/upload/init', { fileName: 'test.apk', fileSize: apkBuf.length, totalChunks }, 'json');
  console.log(`  status=${initRes.status}`, initRes.data);
  if (initRes.status !== 201 && initRes.status !== 200) { console.error('INIT FAILED'); process.exit(1); }
  const uploadId = initRes.data.uploadId;

  // Step 2: Upload chunks
  console.log('\n=== Step 2: upload chunks ===');
  for (let i = 0; i < totalChunks; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, apkBuf.length);
    const chunk = apkBuf.subarray(start, end);
    const mp = buildMultipart({ uploadId, chunkIndex: String(i), chunk });
    const res = await req('POST', '/hardening/upload/chunk', mp);
    console.log(`  chunk ${i}/${totalChunks - 1}: status=${res.status}`);
    if (res.status !== 201 && res.status !== 200) { console.error('CHUNK FAILED', res.data); process.exit(1); }
  }

  // Step 3: Complete
  console.log('\n=== Step 3: upload/complete ===');
  const compRes = await req('POST', '/hardening/upload/complete', { uploadId }, 'json');
  console.log(`  status=${compRes.status}`, compRes.data);
  if (!compRes.data?.fileId) { console.error('COMPLETE FAILED', compRes.data); process.exit(1); }
  const fileId = compRes.data.fileId;

  // Step 4: Analyze
  console.log('\n=== Step 4: analyze ===');
  const analyzeRes = await req('POST', '/hardening/analyze', { fileId }, 'json');
  console.log(`  status=${analyzeRes.status}`, analyzeRes.data);
  if (!analyzeRes.data?.taskId) { console.error('ANALYZE FAILED'); process.exit(1); }
  const analyzeTaskId = analyzeRes.data.taskId;

  // Poll analyze
  console.log('  polling analyze...');
  let analysis = null;
  for (let i = 0; i < 60; i++) {
    await sleep(2000);
    const st = await req('GET', `/hardening/status/${analyzeTaskId}`);
    console.log(`  [${i}] status=${st.data.status} progress=${st.data.progress} step=${st.data.step} msg=${st.data.message}`);
    if (st.data.status === 'completed') { analysis = st.data.analysis; break; }
    if (st.data.status === 'failed') { console.error('ANALYZE FAILED:', st.data.error); process.exit(1); }
  }
  if (!analysis) { console.error('ANALYZE TIMEOUT'); process.exit(1); }
  console.log('  analysis:', JSON.stringify(analysis).slice(0, 200));

  // Step 5: Harden
  console.log('\n=== Step 5: harden ===');
  const config = { productLine: 'xuanjia', preset: 'standard', xuanjia: { x0_soEncrypt: true, x3_lifecycle: true, x4_antiDynamic: true, x5_vpnProxy: true, x6_dualApp: true, x7_privatePort: true, x8_fart: false, x9_odex: false } };
  const ksBuf = fs.readFileSync(KS_PATH);
  const hardenMp = buildMultipart({
    fileId,
    keystore: ksBuf,
    keystorePassword: KS_PASS,
    keyAlias: KS_ALIAS,
    keyPassword: KS_PASS,
    config: JSON.stringify(config),
    analysisJson: JSON.stringify(analysis),
    ownershipConfirmed: 'true',
  });
  const hardenRes = await req('POST', '/hardening/harden', hardenMp);
  console.log(`  status=${hardenRes.status}`, hardenRes.data);
  if (!hardenRes.data?.taskId) { console.error('HARDEN FAILED', hardenRes.data); process.exit(1); }
  const hardenTaskId = hardenRes.data.taskId;

  // Poll harden
  console.log('  polling harden...');
  for (let i = 0; i < 120; i++) {
    await sleep(3000);
    const st = await req('GET', `/hardening/status/${hardenTaskId}`);
    console.log(`  [${i}] status=${st.data.status} progress=${st.data.progress} step=${st.data.step} msg=${st.data.message}`);
    if (st.data.status === 'completed') { console.log('\n✅ HARDENING COMPLETE!'); process.exit(0); }
    if (st.data.status === 'failed') { console.error('\n❌ HARDEN FAILED:', st.data.error); process.exit(1); }
  }
  console.error('HARDEN TIMEOUT');
  process.exit(1);
}

main().catch(e => { console.error('FATAL:', e.message); process.exit(1); });
