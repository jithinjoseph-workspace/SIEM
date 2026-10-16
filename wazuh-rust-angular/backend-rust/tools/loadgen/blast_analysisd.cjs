// Sends Windows events straight to analysisd's queue (what remoted forwards), at fixed rates,
// and reports how many analysisd took in, dropped and decoded. node blast_analysisd.cjs <agent id> <name> <rate,rate,..> <secs each>
const dgram = require('dgram'), fs = require('fs');
const HOME = require('path').join(__dirname, '../../data/manager');
const port = +fs.readFileSync(`${HOME}/queue/sockets/queue.port`, 'utf8').trim();
const [id, name, rates, secs] = [process.argv[2], process.argv[3], process.argv[4].split(',').map(Number), +process.argv[5]];
const st = () => Object.fromEntries(fs.readFileSync(`${HOME}/var/run/wazuh-analysisd.state`, 'utf8').split('\n').filter(l => l.includes("='")).map(l => { const [k, v] = l.split("='"); return [k, v.replace(/'$/, '')]; }));
const ev = (n, err) => `f:[${id}] (${name}) any->EventChannel:{"Message":"m #${n}","Event":"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='LoadTest'/><EventID Qualifiers='0'>${err ? 1000 : 1001}</EventID><Version>0</Version><Level>${err ? 2 : 4}</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='2026-10-16T00:00:00.0000000Z'/><EventRecordID>${n}</EventRecordID><Correlation/><Execution ProcessID='4' ThreadID='0'/><Channel>Application</Channel><Computer>${name}</Computer><Security/></System><EventData><Data>m #${n}</Data></EventData></Event>"}\0`;
const sock = dgram.createSocket('udp4');
sock.connect(port, '127.0.0.1', async () => {
  let n = 0;
  for (const rate of rates) {
    const a = st(), t0 = Date.now();
    let sent = 0;
    while (Date.now() - t0 < secs * 1000) {
      const due = Math.floor((Date.now() - t0) / 1000 * rate);
      while (sent < due) { sock.send(ev(++n, n % 20 === 0)); sent++; }
      await new Promise(r => setImmediate(r));
    }
    await new Promise(r => setTimeout(r, 6000)); // state file is written every 5 s
    const b = st();
    const d = (k) => (+b[k] || 0) - (+a[k] || 0);
    console.log(`rate ${rate}/s: sent ${sent}, analysisd received ${d('events_received')} (${(d('events_received') / secs).toFixed(0)}/s), winevt decoded ${d('winevt_events_decoded')}, dropped ${d('events_dropped')}, alerts ${d('alerts_written')}, winevt queue ${b.winevt_queue_usage}`);
  }
  sock.close();
});
