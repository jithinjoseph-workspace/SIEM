// Enrolls N load-test agents in tenant "loadtest" through POST /api/v1/agents/enroll.
// node enroll.cjs <count> <keys out file> [concurrency] [start index]
// node enroll.cjs delete   -> removes every agent of tenant loadtest
const crypto = require('crypto'), fs = require('fs'), { execFileSync } = require('child_process');
const SECRET = fs.readFileSync(require('path').join(__dirname, '../../data/jwt_secret.txt'), 'utf8').trim();
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jti = crypto.randomUUID(), now = Math.floor(Date.now() / 1000);
execFileSync('docker', ['exec', 'xdr-valkey', 'valkey-cli', 'SET', `ndr:session:${jti}`, '1', 'EX', '7200']);
const body = b64({ alg: 'HS256', typ: 'JWT' }) + '.' + b64({ sub: 'loadtest', role: 'tenant_admin', tenant_id: 'loadtest', permissions: [], features: ['siem'], sensor_ids: [], exp: now + 7200, iat: now, jti });
const T = body + '.' + crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
const H = { Authorization: `Bearer ${T}`, 'Content-Type': 'application/json' };
const API = 'http://127.0.0.1:8088';

(async () => {
  if (process.argv[2] === 'delete') {
    const agents = await (await fetch(`${API}/api/v1/agents`, { headers: H })).json();
    const ids = agents.map(a => a.id);
    let ok = 0, next = 0;
    const worker = async () => { while (next < ids.length) { const id = ids[next++]; const r = await fetch(`${API}/api/v1/agents/${id}`, { method: 'DELETE', headers: H }); if (r.ok) ok++; } };
    await Promise.all(Array.from({ length: 8 }, worker));
    console.log(`deleted ${ok} of ${ids.length} agents of tenant loadtest`);
    return;
  }
  const count = +process.argv[2], out = process.argv[3], conc = +(process.argv[4] || 16), base = +(process.argv[5] || 0);
  const lines = [], lat = [];
  let next = 0, failed = 0;
  const t0 = Date.now();
  const worker = async () => {
    while (next < count) {
      const i = base + next++;
      const t = Date.now();
      try {
        const r = await fetch(`${API}/api/v1/agents/enroll`, { method: 'POST', headers: H, body: JSON.stringify({ name: `lt-${String(i).padStart(5, '0')}`, os_type: 'windows' }) });
        const j = await r.json();
        if (r.ok) lines.push(`${j.agent_id} ${j.agent_name} ${j.agent_ip} ${j.raw_key}`);
        else { failed++; if (failed < 5) console.log('fail', r.status, JSON.stringify(j)); }
      } catch (e) { failed++; }
      lat.push(Date.now() - t);
      if (lat.length % 500 === 0) console.log(`${lat.length} enrolled, ${((Date.now() - t0) / 1000).toFixed(0)} s, last latency ${lat[lat.length - 1]} ms`);
    }
  };
  await Promise.all(Array.from({ length: conc }, worker));
  fs.appendFileSync(out, lines.join('\n') + '\n');
  lat.sort((a, b) => a - b);
  const s = (Date.now() - t0) / 1000;
  console.log(`enrolled ${lines.length}, failed ${failed}, ${s.toFixed(1)} s (${(lines.length / s).toFixed(1)}/s), latency p50 ${lat[lat.length >> 1]} ms p95 ${lat[Math.floor(lat.length * 0.95)]} ms max ${lat[lat.length - 1]} ms`);
})();
