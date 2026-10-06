// The llhttp reference: Node's HTTP parser, driven directly.
//
// llhttp is what Node's http module is built on, and the HTTPParser binding is
// the module's own entry to it, without sockets. Same protocol as
// http_probe.c: tab-separated cases on stdin, one `id split json` line out,
// every string hex.
//
// STRICTNESS. llhttp has lenient flags (kLenientHeaders, kLenientChunkedLength,
// kLenientKeepAlive, ... kLenientAll) that make it accept what its default
// refuses. This driver passes kLenientNone, which is Node's own default, and
// GHTTP_REF_LENIENT=1 passes kLenientAll instead. The second exists only so
// that the gate can show the first is in force: an input that llhttp refuses
// strictly and accepts leniently must change its answer between the two, or the
// flag this driver sets is not the flag llhttp reads (diff.py --controls).
'use strict';

const readline = require('readline');
const { AsyncResource } = require('async_hooks');
const { HTTPParser, methods: METHODS } = process.binding('http_parser');

if (process.argv[2] === '--version') {
  console.log('llhttp ' + process.versions.llhttp + ' node ' + process.versions.node);
  process.exit(0);
}

const LENIENT = process.env.GHTTP_REF_LENIENT === '1'
  ? HTTPParser.kLenientAll : HTTPParser.kLenientNone;
// The head cap, set to this library's default (64 KiB) rather than Node's
// 16 KiB, so that a head between the two is not a disagreement about a limit.
const MAX_HEADER = 65536;

const hex = (s) => Buffer.from(String(s), 'latin1').toString('hex');
const pairs = (flat) => {
  const out = [];
  for (let i = 0; i + 1 < flat.length; i += 2) {
    out.push([hex(flat[i]), hex(flat[i + 1])]);
  }
  return out;
};

function run(isReq, method, data, byte) {
  const parser = new HTTPParser();
  parser.initialize(isReq ? HTTPParser.REQUEST : HTTPParser.RESPONSE,
    new AsyncResource('GHTTP_REF'), MAX_HEADER, LENIENT);
  const msgs = [];
  let cur = null;
  let inHead = true;
  let pend = [];
  let urlAcc = '';
  let pending = method === '-' ? 'GET' : method;
  let stop = false;

  parser[HTTPParser.kOnHeaders] = function (headers, url) {
    if (inHead) {
      pend.push(...headers);
      urlAcc += url;
    } else if (cur) {
      cur.trailers.push(...pairs(headers));
    }
  };
  parser[HTTPParser.kOnHeadersComplete] = function (major, minor, headers, m,
    url, status, message, upgrade) {
    if (headers === undefined) { headers = pend; }
    if (url === undefined) { url = urlAcc; }
    pend = [];
    urlAcc = '';
    inHead = false;
    const start = isReq
      ? { method: hex(METHODS[m]), target: hex(url), ver: major + '.' + minor }
      : { reason: hex(message), status, ver: major + '.' + minor };
    cur = { start, headers: pairs(headers), body: [], trailers: [], upgrade: !!upgrade, done: false };
    if (!isReq) {
      if (status >= 200) {
        const was = pending;
        pending = 'GET';
        if (was === 'CONNECT' && status < 300) { cur.upgrade = true; return 2; }
        if (was === 'HEAD') { return 1; }
      }
    }
    return 0;
  };
  parser[HTTPParser.kOnBody] = function (b) { if (cur) { cur.body.push(Buffer.from(b)); } };
  parser[HTTPParser.kOnMessageComplete] = function () {
    if (cur && !cur.done) { finish(cur); }
  };
  function finish(c) {
    c.done = true;
    msgs.push({ start: c.start, headers: c.headers, body: Buffer.concat(c.body).toString('hex'),
      trailers: c.trailers, upgrade: c.upgrade });
    if (c.upgrade) { stop = true; }
    cur = null;
    // The next message's head may begin in this same execute() call.
    inHead = true;
  }

  let end = 'clean';
  let err = '';
  let eof = false;
  const step = (chunk) => {
    const r = parser.execute(chunk);
    if (r instanceof Error) {
      end = eof ? 'incomplete' : 'error';
      err = r.code || String(r);
      return false;
    }
    return true;
  };

  let ok = true;
  if (byte) {
    for (let i = 0; i < data.length && ok && !stop; i++) {
      ok = step(data.subarray(i, i + 1));
    }
  } else if (data.length) {
    ok = step(data);
  }
  if (ok) {
    eof = true;
    const r = parser.finish();
    if (r instanceof Error && !stop && !(cur && cur.upgrade)) {
      end = 'incomplete';
      err = r.code || String(r);
    }
  }
  if (cur && cur.upgrade && !cur.done) { finish(cur); }
  // An implementation that stopped at a tunnel reports the tunnel, not how
  // the rest of the bytes would have parsed as HTTP.
  if (stop) { end = 'clean'; err = ''; }
  parser.close();
  return { msgs, end, err };
}

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on('line', (line) => {
  if (!line) { return; }
  const f = line.split('\t');
  const result = run(f[1] === 'req', f[2], Buffer.from(f[4], 'hex'), f[3] === 'byte');
  process.stdout.write(f[0] + '\t' + f[3] + '\t' + JSON.stringify(result) + '\n');
});
