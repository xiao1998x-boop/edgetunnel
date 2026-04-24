// ========================================================================
// edgetunnel × Xboard · Cloudflare Pages 单文件版
// 基线: cmliu/edgetunnel (VLESS over WebSocket)
// 能力: UUID 鉴权 / 日流量硬封顶 / 总流量到期 / 订阅链接 / 内置管理 UI
//
// 部署: 把本文件放在 Pages 仓库根目录，commit 后 Pages 自动部署
// 绑定: Dashboard → Pages → 设置 → Functions
//       - D1:  变量名 DB      指向 edgetunnel-mvp 数据库
//       - KV:  变量名 KV      指向你创建的 KV 命名空间
// 环境: Dashboard → Pages → 设置 → Environment variables
//       - ADMIN_TOKEN (secret)  管理页登录 token
//       - PANEL_URL / NODE_ID / PANEL_TOKEN (可选，以后接 Xboard 时加)
// ========================================================================

const WS_POLICY_VIOLATION = 1008;

// ---------- 入口 ----------
export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);

      if (url.pathname === '/admin' || url.pathname === '/admin/') {
        return new Response(ADMIN_HTML, {
          headers: { 'content-type': 'text/html; charset=utf-8' }
        });
      }

      if (url.pathname.startsWith('/sub/')) {
        return handleSubscription(request, env, url);
      }

      if (url.pathname.startsWith('/p/')) {
        return handlePublicPage(request, env, url);
      }

      if (url.pathname.startsWith('/admin/')) {
        return handleAdmin(request, env, url, ctx);
      }

      const upgradeHeader = request.headers.get('Upgrade');
      if (upgradeHeader === 'websocket') {
        // 按 path 分发到 VLESS / Trojan. TROJAN_PATH 命中 => Trojan, 否则默认 VLESS
        const trojanPath = (await getSetting(env, 'TROJAN_PATH')) || '/trojan';
        if (trojanPath && trojanPath !== '/' && (url.pathname === trojanPath || url.pathname.startsWith(trojanPath + '/'))) {
          return trojanOverWSHandler(request, env, ctx);
        }
        return vlessOverWSHandler(request, env, ctx);
      }

      return new Response('OK', { status: 200, headers: { 'content-type': 'text/plain' } });
    } catch (err) {
      return new Response('err: ' + err.message, { status: 500 });
    }
  }
};

// ========================================================================
// 1. VLESS over WebSocket
// ========================================================================

async function vlessOverWSHandler(request, env, ctx) {
  const webSocketPair = new WebSocketPair();
  const [client, server] = Object.values(webSocketPair);
  server.accept();

  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  const readableWebSocketStream = makeReadableWebSocketStream(server, earlyDataHeader);

  const connState = {
    user: null,
    remoteSocketWrapper: { value: null },
    udpStreamWrite: null,
    isDns: false,
    upBytes: 0,
    downBytes: 0,
    startedAt: Date.now(),
  };

  readableWebSocketStream
    .pipeTo(new WritableStream({
      async write(chunk, controller) {
        try {
          if (connState.isDns && connState.udpStreamWrite) {
            connState.upBytes += chunk.byteLength;
            return connState.udpStreamWrite(chunk);
          }
          if (connState.remoteSocketWrapper.value) {
            const writer = connState.remoteSocketWrapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            connState.upBytes += chunk.byteLength;
            return;
          }

          const header = processVlessHeader(chunk);
          if (header.hasError) {
            safeCloseWS(server, WS_POLICY_VIOLATION, header.message);
            return;
          }

          const auth = await authorizeUser(header.uuid, env, ctx);
          if (!auth.ok) {
            safeCloseWS(server, WS_POLICY_VIOLATION, auth.reason);
            return;
          }
          connState.user = auth.user;

          const vlessResponseHeader = new Uint8Array([header.vlessVersion[0], 0]);
          const rawClientData = chunk.slice(header.rawDataIndex);

          if (header.isUDP) {
            if (header.portRemote !== 53) {
              safeCloseWS(server, WS_POLICY_VIOLATION, 'only DNS UDP allowed');
              return;
            }
            connState.isDns = true;
            const { write } = await handleUDPOutBound(server, vlessResponseHeader, connState);
            connState.udpStreamWrite = write;
            connState.udpStreamWrite(rawClientData);
            connState.upBytes += chunk.byteLength;
            return;
          }

          await handleTCPOutBound(
            connState,
            header.addressRemote,
            header.portRemote,
            rawClientData,
            server,
            vlessResponseHeader,
            env
          );
          connState.upBytes += chunk.byteLength;
        } catch (err) {
          safeCloseWS(server, 1011, 'write err: ' + err.message);
        }
      },
      close() { ctx.waitUntil(flushConnectionTraffic(connState, env)); },
      abort() { ctx.waitUntil(flushConnectionTraffic(connState, env)); }
    }))
    .catch(() => { ctx.waitUntil(flushConnectionTraffic(connState, env)); });

  return new Response(null, { status: 101, webSocket: client });
}

// ========================================================================
// 1b. Trojan over WebSocket
// Trojan 帧格式: [56B hex(SHA224(password))][CRLF][cmd:1][atype:1][addr][port:2][CRLF][payload]
// password = 用户 UUID 字符串 (带连字符), Worker 用 SHA-224 哈希验证
// ========================================================================

async function trojanOverWSHandler(request, env, ctx) {
  const webSocketPair = new WebSocketPair();
  const [client, server] = Object.values(webSocketPair);
  server.accept();

  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  const readable = makeReadableWebSocketStream(server, earlyDataHeader);

  const connState = {
    user: null,
    remoteSocketWrapper: { value: null },
    udpStreamWrite: null,
    isDns: false,
    upBytes: 0,
    downBytes: 0,
    startedAt: Date.now(),
  };

  readable
    .pipeTo(new WritableStream({
      async write(chunk, controller) {
        try {
          if (connState.remoteSocketWrapper.value) {
            const writer = connState.remoteSocketWrapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            connState.upBytes += chunk.byteLength;
            return;
          }

          const header = parseTrojanHeader(chunk);
          if (header.hasError) {
            safeCloseWS(server, WS_POLICY_VIOLATION, header.message);
            return;
          }

          const uuid = await resolveTrojanHashToUuid(header.hash, env);
          if (!uuid) {
            safeCloseWS(server, WS_POLICY_VIOLATION, 'trojan: unknown hash');
            return;
          }
          const auth = await authorizeUser(uuid, env, ctx);
          if (!auth.ok) {
            safeCloseWS(server, WS_POLICY_VIOLATION, auth.reason);
            return;
          }
          connState.user = auth.user;

          if (header.isUDP) {
            // Trojan UDP ASSOCIATE 较复杂, MVP 阶段仅支持 TCP
            safeCloseWS(server, WS_POLICY_VIOLATION, 'trojan UDP not supported');
            return;
          }

          await handleTCPOutBound(
            connState,
            header.addressRemote,
            header.portRemote,
            header.payload,
            server,
            null,        // Trojan 不需要回传协议响应头
            env
          );
          connState.upBytes += chunk.byteLength;
        } catch (err) {
          safeCloseWS(server, 1011, 'trojan err: ' + err.message);
        }
      },
      close() { ctx.waitUntil(flushConnectionTraffic(connState, env)); },
      abort() { ctx.waitUntil(flushConnectionTraffic(connState, env)); }
    }))
    .catch(() => { ctx.waitUntil(flushConnectionTraffic(connState, env)); });

  return new Response(null, { status: 101, webSocket: client });
}

function parseTrojanHeader(buffer) {
  if (buffer.byteLength < 60) return { hasError: true, message: 'trojan: short' };
  const view = new DataView(buffer);
  const hashBytes = new Uint8Array(buffer.slice(0, 56));
  // 56 字节 ASCII hex
  const hash = new TextDecoder().decode(hashBytes);
  if (!/^[0-9a-f]{56}$/.test(hash)) return { hasError: true, message: 'trojan: bad hash' };
  if (view.getUint8(56) !== 0x0d || view.getUint8(57) !== 0x0a) {
    return { hasError: true, message: 'trojan: missing CRLF after hash' };
  }
  const cmd = view.getUint8(58);
  const isUDP = cmd === 0x03;
  if (cmd !== 0x01 && cmd !== 0x03) return { hasError: true, message: 'trojan: bad cmd ' + cmd };
  const atype = view.getUint8(59);
  let addrStart = 60, addrLen = 0, addr = '';
  if (atype === 0x01) {        // IPv4
    addrLen = 4;
    addr = new Uint8Array(buffer.slice(addrStart, addrStart + 4)).join('.');
  } else if (atype === 0x03) { // domain
    addrLen = view.getUint8(addrStart);
    addrStart += 1;
    addr = new TextDecoder().decode(buffer.slice(addrStart, addrStart + addrLen));
  } else if (atype === 0x04) { // IPv6
    addrLen = 16;
    const dv2 = new DataView(buffer, addrStart, 16);
    const parts = [];
    for (let i = 0; i < 8; i++) parts.push(dv2.getUint16(i * 2).toString(16));
    addr = parts.join(':');
  } else {
    return { hasError: true, message: 'trojan: bad atype ' + atype };
  }
  const portIdx = addrStart + addrLen;
  if (portIdx + 4 > buffer.byteLength) return { hasError: true, message: 'trojan: truncated' };
  const port = view.getUint16(portIdx);
  if (view.getUint8(portIdx + 2) !== 0x0d || view.getUint8(portIdx + 3) !== 0x0a) {
    return { hasError: true, message: 'trojan: missing CRLF after port' };
  }
  const payload = buffer.slice(portIdx + 4);
  return { hasError: false, hash, isUDP, addressRemote: addr, portRemote: port, payload };
}

// 按 Trojan hash 查用户 UUID. 全表 SHA-224 预计算结果缓存在 KV 60s.
async function resolveTrojanHashToUuid(hash, env) {
  let mapStr = await env.KV.get('trojan_map');
  let map = null;
  if (mapStr) { try { map = JSON.parse(mapStr); } catch {} }
  if (!map) {
    const rs = await env.DB.prepare('SELECT uuid FROM users WHERE enabled = 1').all();
    map = {};
    for (const u of (rs.results || [])) {
      const h = sha224Hex(new TextEncoder().encode(u.uuid));
      map[h] = u.uuid;
    }
    await env.KV.put('trojan_map', JSON.stringify(map), { expirationTtl: 60 });
  }
  return map[hash] || null;
}

// ========================================================================
// SHA-224 纯 JS 实现 (Cloudflare Workers SubtleCrypto 不支持 SHA-224)
// SHA-224 = SHA-256 with 不同 IV + 输出截取前 224 bit
// ========================================================================
const SHA224_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

function sha224Hex(input) {
  // input: Uint8Array
  const data = input instanceof Uint8Array ? input : new Uint8Array(input);
  const H = new Uint32Array([
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
  ]);
  const bitLen = data.length * 8;
  // pad: data || 0x80 || 0..0 || length(64-bit big-endian). total length mod 64 == 56.
  const padLen = (data.length + 9 + 63) & ~63;
  const padded = new Uint8Array(padLen);
  padded.set(data);
  padded[data.length] = 0x80;
  const dv = new DataView(padded.buffer);
  // length in bits, big-endian 64-bit (our inputs << 2^32, so hi=0)
  dv.setUint32(padLen - 4, bitLen >>> 0, false);
  dv.setUint32(padLen - 8, Math.floor(bitLen / 0x100000000), false);

  const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;
  const W = new Uint32Array(64);
  for (let offset = 0; offset < padLen; offset += 64) {
    for (let i = 0; i < 16; i++) W[i] = dv.getUint32(offset + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(W[i-15], 7) ^ rotr(W[i-15], 18) ^ (W[i-15] >>> 3);
      const s1 = rotr(W[i-2], 17) ^ rotr(W[i-2], 19) ^ (W[i-2] >>> 10);
      W[i] = (W[i-16] + s0 + W[i-7] + s1) >>> 0;
    }
    let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = ((e & f) ^ ((~e) & g)) >>> 0;
      const t1 = (h + S1 + ch + SHA224_K[i] + W[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const mj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const t2 = (S0 + mj) >>> 0;
      h = g; g = f; f = e;
      e = (d + t1) >>> 0;
      d = c; c = b; b = a;
      a = (t1 + t2) >>> 0;
    }
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0;
    H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0;
    H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
  }
  // 输出前 7 个字 = 224 bit, big-endian hex
  let s = '';
  for (let i = 0; i < 7; i++) s += H[i].toString(16).padStart(8, '0');
  return s;
}

// ========================================================================
// 2. VLESS 头解析
// ========================================================================

function processVlessHeader(buffer) {
  if (buffer.byteLength < 24) return { hasError: true, message: 'invalid data' };
  const view = new DataView(buffer);
  const version = new Uint8Array(buffer.slice(0, 1));
  const uuid = stringifyUUID(new Uint8Array(buffer.slice(1, 17)));
  const optLength = view.getUint8(17);
  const command = view.getUint8(18 + optLength);
  let isUDP = false;
  if (command === 2) isUDP = true;
  else if (command !== 1) return { hasError: true, message: 'unsupported command ' + command };

  const portIndex = 18 + optLength + 1;
  const portRemote = view.getUint16(portIndex);

  const addressIndex = portIndex + 2;
  const addressType = view.getUint8(addressIndex);
  let addressLen = 0;
  let addressValueIndex = addressIndex + 1;
  let addressRemote = '';

  switch (addressType) {
    case 1:
      addressLen = 4;
      addressRemote = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + addressLen)).join('.');
      break;
    case 2:
      addressLen = view.getUint8(addressValueIndex);
      addressValueIndex += 1;
      addressRemote = new TextDecoder().decode(buffer.slice(addressValueIndex, addressValueIndex + addressLen));
      break;
    case 3:
      addressLen = 16;
      const ipv6 = [];
      const dv = new DataView(buffer.slice(addressValueIndex, addressValueIndex + addressLen));
      for (let i = 0; i < 8; i++) ipv6.push(dv.getUint16(i * 2).toString(16));
      addressRemote = ipv6.join(':');
      break;
    default:
      return { hasError: true, message: 'invalid addressType ' + addressType };
  }

  return {
    hasError: false, uuid, vlessVersion: version, addressType,
    addressRemote, portRemote,
    rawDataIndex: addressValueIndex + addressLen, isUDP,
  };
}

// ========================================================================
// 3. 鉴权 + 懒惰式日流量重置（Pages 无 Cron，用这个代替）
// ========================================================================

async function authorizeUser(uuid, env, ctx) {
  const blocked = await env.KV.get('block:' + uuid);
  if (blocked) return { ok: false, reason: 'blocked:' + blocked };

  let userJson = await env.KV.get('user:' + uuid);
  let user;

  if (userJson) {
    user = JSON.parse(userJson);
  } else {
    const row = await env.DB
      .prepare(`SELECT uuid, panel_user_id, enabled, total_quota_bytes, total_used_bytes,
                       daily_quota_bytes, daily_used_bytes, daily_reset_at,
                       expire_at, conn_limit
                FROM users WHERE uuid = ?`)
      .bind(uuid)
      .first();
    if (!row) return { ok: false, reason: 'unknown uuid' };
    user = row;
    ctx.waitUntil(env.KV.put('user:' + uuid, JSON.stringify(user), { expirationTtl: 120 }));
  }

  if (!user.enabled) return { ok: false, reason: 'disabled' };

  // --- 懒惰式日流量重置 ---
  // 如果上次重置是"今天 UTC 0 点"之前，则把计数清零
  const now = new Date();
  const todayStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  const lastReset = user.daily_reset_at ? new Date(user.daily_reset_at) : new Date(0);
  if (lastReset < todayStart) {
    const iso = now.toISOString();
    // 异步落库 + 清缓存
    ctx.waitUntil((async () => {
      await env.DB
        .prepare(`UPDATE users SET daily_used_bytes = 0, daily_reset_at = ? WHERE uuid = ?`)
        .bind(iso, uuid).run();
      await env.KV.delete('user:' + uuid);
    })());
    // 当前请求内就当已经清零
    user.daily_used_bytes = 0;
  }

  if (user.expire_at && new Date(user.expire_at) < now) {
    ctx.waitUntil(env.KV.put('block:' + uuid, 'expired', { expirationTtl: 86400 }));
    return { ok: false, reason: 'expired' };
  }

  if (user.total_quota_bytes > 0 && user.total_used_bytes >= user.total_quota_bytes) {
    ctx.waitUntil(env.KV.put('block:' + uuid, 'total_exceeded', { expirationTtl: 3600 }));
    return { ok: false, reason: 'total_quota_exceeded' };
  }

  if (user.daily_quota_bytes > 0 && user.daily_used_bytes >= user.daily_quota_bytes) {
    const midnight = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1));
    const ttl = Math.max(60, Math.floor((midnight.getTime() - now.getTime()) / 1000));
    ctx.waitUntil(env.KV.put('block:' + uuid, 'daily_exceeded', { expirationTtl: ttl }));
    return { ok: false, reason: 'daily_quota_exceeded' };
  }

  const sessId = crypto.randomUUID().slice(0, 8);
  ctx.waitUntil(env.KV.put(`sess:${uuid}:${sessId}`, '1', { expirationTtl: 90 }));

  return { ok: true, user };
}

// ========================================================================
// 4. TCP / UDP 转发
// ========================================================================

async function handleTCPOutBound(connState, addr, port, rawClientData, ws, vlessResponseHeader, env) {
  const { connect } = await import('cloudflare:sockets');

  async function dial(targetAddr, targetPort) {
    const tcpSocket = connect({ hostname: targetAddr, port: targetPort });
    connState.remoteSocketWrapper.value = tcpSocket;
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket;
  }

  // 动态读取 PROXYIP (优先从 D1 settings, fallback 到 env var, 再 fallback 到无)
  const proxyIp = await getSetting(env, 'PROXYIP') || env.PROXY_IP || '';

  async function retryViaProxy() {
    if (!proxyIp) return;
    try {
      // PROXYIP 支持 host:port 或纯 host
      const [phost, pport] = proxyIp.includes(':') ? proxyIp.split(':') : [proxyIp, port];
      const sock = await dial(phost, Number(pport) || port);
      pumpRemoteToWS(sock, ws, vlessResponseHeader, connState, null);
    } catch {}
  }

  const tcpSocket = await dial(addr, port);
  pumpRemoteToWS(tcpSocket, ws, vlessResponseHeader, connState, retryViaProxy);
}

// ---------- 节点设置读取 (带 60s KV 缓存) ----------
async function getSetting(env, key) {
  const cacheKey = 'setting:' + key;
  const cached = await env.KV.get(cacheKey);
  if (cached !== null) return cached;
  const row = await env.DB.prepare('SELECT value FROM settings WHERE key = ?').bind(key).first();
  const val = row?.value ?? '';
  await env.KV.put(cacheKey, val, { expirationTtl: 60 });
  return val;
}

async function getAllSettings(env) {
  const rows = await env.DB.prepare('SELECT key, value FROM settings').all();
  const out = {};
  for (const r of (rows.results || [])) out[r.key] = r.value;
  return out;
}

async function setSetting(env, key, value) {
  await env.DB.prepare(
    `INSERT INTO settings (key, value, updated_at) VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`
  ).bind(key, value).run();
  await env.KV.delete('setting:' + key);
  if (key === 'ADDAPI' || key === 'ADDCSV') await env.KV.delete('optimized_ips');
}

// ---------- 节点属性解析: 备注里的 [key=val,...] 语法 ----------
// 支持: region=us, tag=premium|fast, proto=vless|trojan
// 例: "visa.com:443#美国-CF优选 [region=us,tag=premium,proto=vless]"
function parseNodeLine(line, defaultName, source) {
  // 先把行末的 [attrs] 剥离, 因为 [] 可能贴在 addr 或 remark 后面
  let work = line.trim();
  let attrBlock = '';
  const mAttr = work.match(/^(.*?)\s*\[([^\]]*)\]\s*$/);
  if (mAttr) { work = mAttr[1].trim(); attrBlock = mAttr[2]; }

  // 再切 # 备注
  const firstHash = work.indexOf('#');
  const addrPart = firstHash >= 0 ? work.slice(0, firstHash).trim() : work;
  const remark   = firstHash >= 0 ? work.slice(firstHash + 1).trim() : '';

  const [addrS, portS] = addrPart.split(':');
  const addr = addrS?.trim();
  if (!addr) return null;

  const attrs = {};
  if (attrBlock) {
    for (const kv of attrBlock.split(',')) {
      const [k, v] = kv.split('=').map(s => s && s.trim());
      if (!k || v === undefined) continue;
      if (k === 'tag' || k === 'proto') {
        attrs[k] = (attrs[k] || []).concat(v.split('|').map(s => s.trim()).filter(Boolean));
      } else {
        attrs[k] = v;
      }
    }
  }

  return {
    addr,
    port: Number(portS) || 443,
    name: remark || defaultName,
    region: (attrs.region || 'auto').toLowerCase(),
    tags: attrs.tag || [],
    protos: attrs.proto || null,   // null = 跟随全局 ENABLED_PROTOCOLS
    source,
  };
}

// Cloudflare 机房代码 → 地区. 订阅里 csv 如果有 colo 字段自动推断地区.
const COLO_TO_REGION = {
  // 北美
  LAX:'us', SJC:'us', SEA:'us', DFW:'us', IAD:'us', ATL:'us', ORD:'us', EWR:'us', MIA:'us', DEN:'us', MCI:'us', SLC:'us', PHX:'us', BOS:'us', FLL:'us', LAS:'us', BNA:'us', DTW:'us', PDX:'us', MSP:'us', SMF:'us',
  YYZ:'ca', YVR:'ca', YUL:'ca',
  // 东亚
  HKG:'hk', NRT:'jp', KIX:'jp', HND:'jp', ITM:'jp', ICN:'kr', GMP:'kr', TPE:'tw', TSA:'tw',
  // 东南亚
  SIN:'sg', KUL:'my', BKK:'th', MNL:'ph', CGK:'id', HAN:'vn', SGN:'vn',
  // 南亚
  MUM:'in', DEL:'in', BLR:'in', MAA:'in', HYD:'in', CCU:'in',
  // 欧洲
  LHR:'gb', MAN:'gb', EDI:'gb', AMS:'nl', FRA:'de', DUS:'de', HAM:'de', MUC:'de', TXL:'de', CDG:'fr', MRS:'fr', MAD:'es', BCN:'es', MXP:'it', FCO:'it', WAW:'pl', ARN:'se', OSL:'no', CPH:'dk', HEL:'fi', DUB:'ie', VIE:'at', ZRH:'ch', BRU:'be', LIS:'pt', PRG:'cz', BUD:'hu', OTP:'ro', SOF:'bg', ATH:'gr',
  // 大洋洲
  SYD:'au', MEL:'au', PER:'au', BNE:'au', AKL:'nz',
  // 中东/非洲
  DXB:'ae', TLV:'il', DOH:'qa', KWI:'kw', JNB:'za', CAI:'eg', LOS:'ng',
  // 南美
  GIG:'br', GRU:'br', EZE:'ar', SCL:'cl', BOG:'co', LIM:'pe',
  // 俄罗斯
  DME:'ru', SVO:'ru', LED:'ru',
};

function colosToRegion(colo) {
  if (!colo) return 'auto';
  const k = String(colo).toUpperCase().trim().slice(0, 3);
  return COLO_TO_REGION[k] || 'auto';
}

// ---------- 从 ADDAPI / ADDCSV 拉优选 IP, KV 缓存 10 分钟 ----------
async function fetchOptimizedAddresses(env, settings) {
  const cached = await env.KV.get('optimized_ips');
  if (cached !== null) {
    try { return JSON.parse(cached); } catch {}
  }
  const list = [];

  // ADDAPI: 每行 addr[:port][#备注 [region=xx,tag=yy,proto=zz]]
  // 支持 URL 行里整源标签: "https://xxx.com/us.txt [region=us,tag=usa-pool]"
  const addapiRaw = (settings.ADDAPI || '').split(/\r?\n/);
  for (const rawLine of addapiRaw) {
    const t = rawLine.trim();
    if (!t || t.startsWith('#')) continue;
    // 整源标签: URL 后可跟 [attrs] 覆盖默认
    let url = t;
    let sourceAttrs = {};
    const srcMatch = t.match(/^(\S+)\s*\[([^\]]*)\]\s*$/);
    if (srcMatch) {
      url = srcMatch[1];
      for (const kv of srcMatch[2].split(',')) {
        const [k, v] = kv.split('=').map(s => s && s.trim());
        if (k && v !== undefined) sourceAttrs[k] = v;
      }
    }
    if (!/^https?:\/\//.test(url)) continue;
    try {
      const r = await fetch(url, { cf: { cacheTtl: 300 } });
      if (!r.ok) continue;
      const txt = await r.text();
      let idx = 0;
      for (const line of txt.split(/\r?\n/)) {
        const l = line.trim();
        if (!l || l.startsWith('#')) continue;
        const n = parseNodeLine(l, `addapi-${idx + 1}`, 'addapi');
        if (!n) continue;
        // 整源属性补缺: 节点没写 region/tag 时用源的
        if (n.region === 'auto' && sourceAttrs.region) n.region = sourceAttrs.region.toLowerCase();
        if (sourceAttrs.tag) n.tags = [...new Set([...(n.tags || []), ...sourceAttrs.tag.split('|').map(s => s.trim()).filter(Boolean)])];
        if (!n.protos && sourceAttrs.proto) n.protos = sourceAttrs.proto.split('|').map(s => s.trim()).filter(Boolean);
        list.push(n);
        idx++;
      }
    } catch {}
  }

  // ADDCSV: iptest 格式 CSV. header 一般: ip,port,tls,colo,avgLatency,lossRate,speed  (colo 可在不同列)
  // 读 header 找 colo / region / tls 列索引, 只取 tls=TRUE
  const addcsvRaw = (settings.ADDCSV || '').split(/\r?\n/);
  for (const rawLine of addcsvRaw) {
    const t = rawLine.trim();
    if (!t || t.startsWith('#')) continue;
    let url = t;
    let sourceAttrs = {};
    const srcMatch = t.match(/^(\S+)\s*\[([^\]]*)\]\s*$/);
    if (srcMatch) {
      url = srcMatch[1];
      for (const kv of srcMatch[2].split(',')) {
        const [k, v] = kv.split('=').map(s => s && s.trim());
        if (k && v !== undefined) sourceAttrs[k] = v;
      }
    }
    if (!/^https?:\/\//.test(url)) continue;
    try {
      const r = await fetch(url, { cf: { cacheTtl: 300 } });
      if (!r.ok) continue;
      const txt = await r.text();
      const lines = txt.split(/\r?\n/);
      if (!lines.length) continue;
      // 解析 header
      const header = lines[0].split(',').map(s => s.trim().toLowerCase());
      const iIp   = header.findIndex(h => h === 'ip' || h === 'addr' || h === 'address');
      const iPort = header.findIndex(h => h === 'port');
      const iTls  = header.findIndex(h => h === 'tls');
      const iColo = header.findIndex(h => h === 'colo' || h === 'datacenter' || h === 'dc');
      const iRegion = header.findIndex(h => h === 'region' || h === 'country');
      const iLat  = header.findIndex(h => h.includes('latency') || h.includes('delay'));
      for (let r = 1; r < lines.length; r++) {
        if (!lines[r].trim()) continue;
        const cols = lines[r].split(',').map(s => s.trim());
        const ip = iIp >= 0 ? cols[iIp] : cols[0];
        const portStr = iPort >= 0 ? cols[iPort] : cols[1];
        const tls = iTls >= 0 ? cols[iTls] : cols[2];
        if (!ip) continue;
        if (tls && !/^(true|1|yes)$/i.test(tls)) continue;
        const colo = iColo >= 0 ? cols[iColo] : '';
        const regionDirect = iRegion >= 0 ? cols[iRegion] : '';
        let region = regionDirect ? regionDirect.toLowerCase() : colosToRegion(colo);
        if (sourceAttrs.region) region = sourceAttrs.region.toLowerCase();   // 整源覆盖
        const latency = iLat >= 0 ? cols[iLat] : '';
        const tags = [];
        if (sourceAttrs.tag) tags.push(...sourceAttrs.tag.split('|').map(s => s.trim()).filter(Boolean));
        if (colo) tags.push('colo-' + colo.toUpperCase());
        const name = colo ? `${colo.toUpperCase()}-${ip}` : ip;
        list.push({
          addr: ip,
          port: Number(portStr) || 443,
          name,
          region,
          tags,
          protos: sourceAttrs.proto ? sourceAttrs.proto.split('|').map(s => s.trim()).filter(Boolean) : null,
          source: 'addcsv',
          latency: latency ? Number(latency) || null : null,
        });
      }
    } catch {}
  }

  // 去重 (addr:port 作 key). 上限提到 200 ( 订阅端通过 NODE_FILTER.total_max 再截断 )
  const seen = new Set();
  const uniq = [];
  for (const n of list) {
    const k = n.addr + ':' + n.port;
    if (seen.has(k)) continue;
    seen.add(k);
    uniq.push(n);
    if (uniq.length >= 200) break;
  }

  await env.KV.put('optimized_ips', JSON.stringify(uniq), { expirationTtl: 600 });
  return uniq;
}

// ---------- 节点筛选 (地区 / 标签 / 协议 / 限额) ----------
// filter = { regions, exclude_regions, include_tags, exclude_tags, max_per_region, total_max }
// overrides: 来自 URL 参数 (region=us,hk 覆盖 regions; tag=premium 覆盖 include_tags)
function applyNodeFilter(nodes, filter, overrides) {
  const f = filter || {};
  const regions = (overrides?.regions?.length ? overrides.regions : (f.regions || []))
    .map(s => s.toLowerCase());
  const excludeRegions = (f.exclude_regions || []).map(s => s.toLowerCase());
  const includeTags = overrides?.tags?.length ? overrides.tags : (f.include_tags || []);
  const excludeTags = f.exclude_tags || [];
  const maxPerRegion = Number(f.max_per_region) || 0;
  const totalMax = Number(f.total_max) || 0;

  let out = nodes;
  if (regions.length)         out = out.filter(n => regions.includes((n.region || 'auto').toLowerCase()));
  if (excludeRegions.length)  out = out.filter(n => !excludeRegions.includes((n.region || 'auto').toLowerCase()));
  if (includeTags.length)     out = out.filter(n => (n.tags || []).some(t => includeTags.includes(t)));
  if (excludeTags.length)     out = out.filter(n => !(n.tags || []).some(t => excludeTags.includes(t)));

  if (maxPerRegion > 0) {
    const byR = {};
    out = out.filter(n => {
      const r = (n.region || 'auto').toLowerCase();
      byR[r] = (byR[r] || 0) + 1;
      return byR[r] <= maxPerRegion;
    });
  }
  if (totalMax > 0) out = out.slice(0, totalMax);
  return out;
}

// 解析 settings.NODE_FILTER (JSON 字符串), 失败则回默认
function parseNodeFilter(raw) {
  if (!raw) return { regions: [], exclude_regions: [], include_tags: [], exclude_tags: [], max_per_region: 0, total_max: 60 };
  try {
    const o = JSON.parse(raw);
    return {
      regions: Array.isArray(o.regions) ? o.regions : [],
      exclude_regions: Array.isArray(o.exclude_regions) ? o.exclude_regions : [],
      include_tags: Array.isArray(o.include_tags) ? o.include_tags : [],
      exclude_tags: Array.isArray(o.exclude_tags) ? o.exclude_tags : [],
      max_per_region: Number(o.max_per_region) || 0,
      total_max: Number(o.total_max) || 60,
    };
  } catch {
    return { regions: [], exclude_regions: [], include_tags: [], exclude_tags: [], max_per_region: 0, total_max: 60 };
  }
}

function pumpRemoteToWS(remoteSocket, ws, responseHeader, connState, retry) {
  // responseHeader: Uint8Array (VLESS) 或 null (Trojan, 无需回传协议头)
  let headerSent = !responseHeader;
  let hasIncoming = false;

  remoteSocket.readable
    .pipeTo(new WritableStream({
      async write(chunk) {
        hasIncoming = true;
        if (ws.readyState !== 1) throw new Error('ws closed');
        if (!headerSent && responseHeader) {
          const merged = new Uint8Array(responseHeader.byteLength + chunk.byteLength);
          merged.set(responseHeader, 0);
          merged.set(new Uint8Array(chunk), responseHeader.byteLength);
          ws.send(merged.buffer);
          headerSent = true;
          connState.downBytes += merged.byteLength;
        } else {
          ws.send(chunk);
          connState.downBytes += chunk.byteLength;
        }
      },
      close() { safeCloseWS(ws); },
      abort() { safeCloseWS(ws); }
    }))
    .catch(() => {
      if (!hasIncoming && retry) retry();
      safeCloseWS(ws);
    });
}

async function handleUDPOutBound(ws, vlessResponseHeader, connState) {
  let headerSent = false;
  const transformStream = new TransformStream({
    transform(chunk, controller) {
      for (let i = 0; i < chunk.byteLength; ) {
        const len = new DataView(chunk.buffer, chunk.byteOffset + i, 2).getUint16(0);
        const data = new Uint8Array(chunk.buffer, chunk.byteOffset + i + 2, len);
        i += 2 + len;
        controller.enqueue(data);
      }
    }
  });

  transformStream.readable
    .pipeTo(new WritableStream({
      async write(chunk) {
        const resp = await fetch('https://1.1.1.1/dns-query', {
          method: 'POST',
          headers: { 'content-type': 'application/dns-message' },
          body: chunk,
        });
        const dnsBody = new Uint8Array(await resp.arrayBuffer());
        const sizeBuf = new Uint8Array([(dnsBody.length >> 8) & 0xff, dnsBody.length & 0xff]);
        if (ws.readyState === 1) {
          if (!headerSent) {
            const merged = new Uint8Array(vlessResponseHeader.byteLength + sizeBuf.byteLength + dnsBody.byteLength);
            merged.set(vlessResponseHeader, 0);
            merged.set(sizeBuf, vlessResponseHeader.byteLength);
            merged.set(dnsBody, vlessResponseHeader.byteLength + sizeBuf.byteLength);
            ws.send(merged.buffer);
            headerSent = true;
            connState.downBytes += merged.byteLength;
          } else {
            const merged = new Uint8Array(sizeBuf.byteLength + dnsBody.byteLength);
            merged.set(sizeBuf, 0);
            merged.set(dnsBody, sizeBuf.byteLength);
            ws.send(merged.buffer);
            connState.downBytes += merged.byteLength;
          }
        }
      }
    }))
    .catch(() => safeCloseWS(ws));

  const writer = transformStream.writable.getWriter();
  return { write: (chunk) => writer.write(chunk).catch(() => {}) };
}

// ========================================================================
// 5. 流量落库
// ========================================================================

async function flushConnectionTraffic(connState, env) {
  if (!connState.user) return;
  const up = connState.upBytes, down = connState.downBytes;
  if (up === 0 && down === 0) return;
  const total = up + down;
  const uuid = connState.user.uuid;
  const now = new Date().toISOString();

  try {
    await env.DB
      .prepare(`UPDATE users
                SET daily_used_bytes = daily_used_bytes + ?,
                    total_used_bytes = total_used_bytes + ?,
                    updated_at = ?
                WHERE uuid = ?`)
      .bind(total, total, now, uuid).run();

    await env.DB
      .prepare(`INSERT INTO traffic_buffer (uuid, up_bytes, down_bytes, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(uuid) DO UPDATE SET
                  up_bytes = up_bytes + excluded.up_bytes,
                  down_bytes = down_bytes + excluded.down_bytes,
                  updated_at = excluded.updated_at`)
      .bind(uuid, up, down, now).run();

    await env.KV.delete('user:' + uuid);
  } catch (err) {
    console.log('flush err', uuid, err.message);
  }
}

// ========================================================================
// 6. 面板同步（Pages 无 Cron；保留函数，靠 /admin/sync-now 手动或外部定时触发）
// ========================================================================

async function pullUsersFromPanel(env) {
  if (!env.PANEL_URL || !env.PANEL_TOKEN) return { skipped: 'panel not configured' };
  const url = `${env.PANEL_URL}/api/v1/server/vless/config?node_id=${env.NODE_ID}&token=${env.PANEL_TOKEN}`;
  const resp = await fetch(url, { headers: { 'accept': 'application/json' } });
  if (!resp.ok) {
    await setNodeState(env, 'last_error', `pullUsers ${resp.status}`);
    return { error: resp.status };
  }
  const data = await resp.json();
  const users = data.users || data.data?.users || [];

  const now = new Date().toISOString();
  const stmts = users.map(u => {
    let enabled = 1;
    if (u.enable === false || u.enable === 0) enabled = 0;
    else if (u.banned === true || u.banned === 1) enabled = 0;

    return env.DB.prepare(
      `INSERT INTO users (uuid, panel_user_id, email, enabled,
         total_quota_bytes, daily_quota_bytes, expire_at, conn_limit, speed_limit_kbps, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(uuid) DO UPDATE SET
         panel_user_id = excluded.panel_user_id, email = excluded.email,
         enabled = excluded.enabled,
         total_quota_bytes = excluded.total_quota_bytes,
         daily_quota_bytes = excluded.daily_quota_bytes,
         expire_at = excluded.expire_at, conn_limit = excluded.conn_limit,
         speed_limit_kbps = excluded.speed_limit_kbps,
         updated_at = excluded.updated_at`
    ).bind(u.uuid, u.id, u.email || null, enabled,
           u.transfer_enable || 0, u.daily_limit || 0,
           u.expired_at || null, u.device_limit || 0, u.speed_limit || 0, now);
  });

  if (stmts.length) await env.DB.batch(stmts);

  for (const u of users) {
    const fresh = await env.DB
      .prepare(`SELECT uuid, panel_user_id, enabled, total_quota_bytes, total_used_bytes,
                       daily_quota_bytes, daily_used_bytes, daily_reset_at, expire_at, conn_limit
                FROM users WHERE uuid = ?`).bind(u.uuid).first();
    if (fresh) await env.KV.put('user:' + u.uuid, JSON.stringify(fresh), { expirationTtl: 120 });
  }

  await setNodeState(env, 'last_pull_users_at', now);
  await setNodeState(env, 'last_sync_user_count', String(users.length));
  return { synced: users.length };
}

async function pushTrafficToPanel(env) {
  if (!env.PANEL_URL || !env.PANEL_TOKEN) return { skipped: 'panel not configured' };
  const rows = await env.DB
    .prepare(`SELECT b.uuid, b.up_bytes, b.down_bytes, u.panel_user_id
              FROM traffic_buffer b JOIN users u ON u.uuid = b.uuid
              WHERE b.up_bytes > 0 OR b.down_bytes > 0`).all();
  const data = rows.results || [];
  if (data.length === 0) return { pushed: 0 };

  const payload = {};
  for (const r of data) payload[r.panel_user_id] = [r.up_bytes, r.down_bytes];

  const url = `${env.PANEL_URL}/api/v1/server/vless/push?node_id=${env.NODE_ID}&token=${env.PANEL_TOKEN}`;
  const resp = await fetch(url, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!resp.ok) {
    await setNodeState(env, 'last_error', `pushTraffic ${resp.status}`);
    return { error: resp.status };
  }

  const uuids = data.map(r => r.uuid);
  for (let i = 0; i < uuids.length; i += 50) {
    const ck = uuids.slice(i, i + 50);
    const placeholders = ck.map(() => '?').join(',');
    await env.DB
      .prepare(`UPDATE traffic_buffer SET up_bytes = 0, down_bytes = 0 WHERE uuid IN (${placeholders})`)
      .bind(...ck).run();
  }

  await setNodeState(env, 'last_push_traffic_at', new Date().toISOString());
  return { pushed: data.length };
}

async function setNodeState(env, key, value) {
  await env.DB
    .prepare(`INSERT INTO node_state (key, value, updated_at) VALUES (?, ?, ?)
              ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`)
    .bind(key, value, new Date().toISOString()).run();
}

// ========================================================================
// 7. 订阅端点：/sub/{uuid}
// ========================================================================

async function handleSubscription(request, env, url) {
  const uuid = url.pathname.slice('/sub/'.length);
  if (!uuid) return new Response('missing uuid', { status: 400 });

  const row = await env.DB
    .prepare(`SELECT uuid, email, enabled, expire_at,
                     total_quota_bytes, total_used_bytes
              FROM users WHERE uuid = ?`).bind(uuid).first();
  if (!row || !row.enabled) return new Response('', { status: 404 });
  if (row.expire_at && new Date(row.expire_at) < new Date()) {
    return new Response('', { status: 410 });
  }

  // 读节点设置
  const settings = await getAllSettings(env);
  const host = url.host;
  const wsPath = settings.WS_PATH || '/';
  const prefix = settings.NODE_NAME_PREFIX || 'node';

  // 解析本地地址列表, 一行一个, 格式 addr[:port][#备注] [key=val,...]
  const addrLines = (settings.ADDRESSES || '').split(/\r?\n/).map(s => s.trim()).filter(l => l && !l.startsWith('#'));
  let nodes = [];
  addrLines.forEach((line, i) => {
    const n = parseNodeLine(line, `${prefix}-${i + 1}`, 'local');
    if (n) nodes.push(n);
  });

  // 拼上 ADDAPI/ADDCSV 远程拉到的优选 IP
  try {
    const optimized = await fetchOptimizedAddresses(env, settings);
    optimized.forEach((n, i) => {
      nodes.push({
        ...n,
        name: `${prefix}-优选-${i + 1}-${n.name}`.slice(0, 48),
      });
    });
  } catch {}

  // 兜底: 一个节点都没有, 就用当前 host
  if (nodes.length === 0) {
    nodes.push({ addr: host, port: 443, name: prefix, region: 'auto', tags: [], protos: null, source: 'fallback' });
  }

  // --- 节点筛选 (在优选池里再次筛选) ---
  const filter = parseNodeFilter(settings.NODE_FILTER);
  // URL 参数覆盖: ?region=us,hk  ?tag=premium,fast  ?limit=20
  const overrideRegions = (url.searchParams.get('region') || '').split(',').map(s => s.trim()).filter(Boolean);
  const overrideTags    = (url.searchParams.get('tag')    || '').split(',').map(s => s.trim()).filter(Boolean);
  const overrideLimit   = Number(url.searchParams.get('limit')) || 0;
  const overrides = { regions: overrideRegions, tags: overrideTags };
  nodes = applyNodeFilter(nodes, filter, overrides);
  if (overrideLimit > 0) nodes = nodes.slice(0, overrideLimit);
  if (nodes.length === 0) {
    // 筛空了, 兜底当前 host 避免空订阅
    nodes.push({ addr: host, port: 443, name: prefix, region: 'auto', tags: [], protos: null, source: 'fallback' });
  }

  // --- 协议启用状态 ---
  const enabledProtos = (settings.ENABLED_PROTOCOLS || 'vless')
    .split(/[,\s]+/).map(s => s.trim().toLowerCase()).filter(Boolean);
  const useVless  = enabledProtos.includes('vless');
  const useTrojan = enabledProtos.includes('trojan');
  const trojanPath = settings.TROJAN_PATH || '/trojan';

  // ?proto=vless 或 ?proto=trojan 可手动筛单协议 (不改变启用开关)
  const protoFilter = (url.searchParams.get('proto') || '').toLowerCase();
  const outVless  = useVless  && protoFilter !== 'trojan';
  const outTrojan = useTrojan && protoFilter !== 'vless';

  // --- 格式解析: 显式 ?sub= > User-Agent 自动识别 > 默认 base64 ---
  let format = (url.searchParams.get('sub') || url.searchParams.get('format') || '').toLowerCase();
  if (!format) {
    const ua = (request.headers.get('user-agent') || '').toLowerCase();
    if (/clash|mihomo|stash/.test(ua))                    format = 'clash';
    else if (/sing-?box|sfa|sfi|sfm|sing_box/.test(ua))   format = 'singbox';
    else if (/shadowrocket/.test(ua))                     format = 'plain';
    else                                                   format = 'vless';   // v2rayN/NG 默认吃 base64
  }
  const sni = host;
  const wsHost = host;   // WS host 头统一用 Pages 域名 (sni 走 CF)

  // 构造 URI 列表 (每个节点 × 每个启用协议)
  // 节点级协议限制: n.protos=['vless'] 表示此节点只出 vless
  const uris = [];
  for (const n of nodes) {
    const nodeProtos = Array.isArray(n.protos) && n.protos.length ? n.protos : null;
    const allowVless  = outVless  && (!nodeProtos || nodeProtos.includes('vless'));
    const allowTrojan = outTrojan && (!nodeProtos || nodeProtos.includes('trojan'));
    const bothOut = allowVless && allowTrojan;
    if (allowVless) {
      uris.push(`vless://${uuid}@${n.addr}:${n.port}?encryption=none&security=tls&type=ws&host=${wsHost}&path=${encodeURIComponent(wsPath)}&sni=${sni}#${encodeURIComponent(n.name + (bothOut ? '-vless' : ''))}`);
    }
    if (allowTrojan) {
      uris.push(`trojan://${uuid}@${n.addr}:${n.port}?security=tls&type=ws&host=${wsHost}&path=${encodeURIComponent(trojanPath)}&sni=${sni}#${encodeURIComponent(n.name + (bothOut ? '-trojan' : ''))}`);
    }
  }
  if (uris.length === 0) {
    // 没协议启用 / 节点协议全过滤掉 => 至少给 vless 避免空订阅
    for (const n of nodes) {
      uris.push(`vless://${uuid}@${n.addr}:${n.port}?encryption=none&security=tls&type=ws&host=${wsHost}&path=${encodeURIComponent(wsPath)}&sni=${sni}#${encodeURIComponent(n.name)}`);
    }
  }

  const subInfoHeaders = {
    'content-type': 'text/plain; charset=utf-8',
    'subscription-userinfo': buildSubUserInfo(row),
    'profile-update-interval': '24',
  };

  const protoOpts = { vless: outVless, trojan: outTrojan, trojanPath };

  // --- 格式分发 ---
  if (format === 'plain') {
    return new Response(uris.join('\n'), { headers: subInfoHeaders });
  }

  if (format === 'clash') {
    const yaml = buildClashYaml(nodes, uuid, wsHost, wsPath, sni, prefix, protoOpts);
    return new Response(yaml, { headers: { ...subInfoHeaders, 'content-type': 'text/yaml; charset=utf-8' } });
  }

  if (format === 'singbox' || format === 'sing-box') {
    const json = buildSingBoxConfig(nodes, uuid, wsHost, wsPath, sni, protoOpts);
    return new Response(json, { headers: { ...subInfoHeaders, 'content-type': 'application/json; charset=utf-8' } });
  }

  // 默认 base64 (v2rayN / Shadowrocket / v2rayNG 都吃)
  const b64 = btoa(unescape(encodeURIComponent(uris.join('\n') + '\n')));
  return new Response(b64, { headers: subInfoHeaders });
}

function buildClashYaml(nodes, uuid, wsHost, wsPath, sni, groupName, protoOpts) {
  // protoOpts = { vless: bool, trojan: bool, trojanPath: string }
  const opts = protoOpts || { vless: true, trojan: false };
  const proxies = [];
  for (const n of nodes) {
    const nodeProtos = Array.isArray(n.protos) && n.protos.length ? n.protos : null;
    const allowVless  = opts.vless  && (!nodeProtos || nodeProtos.includes('vless'));
    const allowTrojan = opts.trojan && (!nodeProtos || nodeProtos.includes('trojan'));
    const bothOut = allowVless && allowTrojan;
    if (allowVless) {
      proxies.push({
        kind: 'vless',
        name: n.name + (bothOut ? '-vless' : ''),
        server: n.addr, port: n.port, uuid, sni, wsHost,
        path: wsPath,
      });
    }
    if (allowTrojan) {
      proxies.push({
        kind: 'trojan',
        name: n.name + (bothOut ? '-trojan' : ''),
        server: n.addr, port: n.port, password: uuid, sni, wsHost,
        path: opts.trojanPath || '/trojan',
      });
    }
  }
  if (proxies.length === 0) {
    // 无协议启用 / 节点协议都过滤掉, 兜底 vless
    for (const n of nodes) {
      proxies.push({ kind: 'vless', name: n.name, server: n.addr, port: n.port, uuid, sni, wsHost, path: wsPath });
    }
  }
  const names = proxies.map(p => p.name);
  const y = [];
  y.push('# Auto-generated by edgetunnel-mvp');
  y.push('port: 7890');
  y.push('socks-port: 7891');
  y.push('allow-lan: false');
  y.push('mode: rule');
  y.push('log-level: info');
  y.push('proxies:');
  for (const p of proxies) {
    y.push(`  - name: "${p.name}"`);
    y.push(`    type: ${p.kind}`);
    y.push(`    server: ${p.server}`);
    y.push(`    port: ${p.port}`);
    if (p.kind === 'vless') {
      y.push(`    uuid: ${p.uuid}`);
      y.push(`    tls: true`);
      y.push(`    servername: ${p.sni}`);
      y.push(`    network: ws`);
      y.push(`    ws-opts:`);
      y.push(`      path: "${p.path}"`);
      y.push(`      headers:`);
      y.push(`        Host: ${p.wsHost}`);
      y.push(`    udp: true`);
    } else { // trojan
      y.push(`    password: ${p.password}`);
      y.push(`    sni: ${p.sni}`);
      y.push(`    skip-cert-verify: false`);
      y.push(`    network: ws`);
      y.push(`    ws-opts:`);
      y.push(`      path: "${p.path}"`);
      y.push(`      headers:`);
      y.push(`        Host: ${p.wsHost}`);
      y.push(`    udp: true`);
    }
  }
  y.push('proxy-groups:');
  y.push(`  - name: "${groupName || 'PROXY'}"`);
  y.push(`    type: select`);
  y.push(`    proxies:`);
  y.push(`      - "AUTO"`);
  for (const n of names) y.push(`      - "${n}"`);
  y.push(`  - name: "AUTO"`);
  y.push(`    type: url-test`);
  y.push(`    url: http://www.gstatic.com/generate_204`);
  y.push(`    interval: 300`);
  y.push(`    proxies:`);
  for (const n of names) y.push(`      - "${n}"`);
  y.push('rules:');
  y.push(`  - MATCH,${groupName || 'PROXY'}`);
  return y.join('\n') + '\n';
}

function buildSingBoxConfig(nodes, uuid, wsHost, wsPath, sni, protoOpts) {
  const opts = protoOpts || { vless: true, trojan: false };
  const outbounds = [];
  for (const n of nodes) {
    const nodeProtos = Array.isArray(n.protos) && n.protos.length ? n.protos : null;
    const allowVless  = opts.vless  && (!nodeProtos || nodeProtos.includes('vless'));
    const allowTrojan = opts.trojan && (!nodeProtos || nodeProtos.includes('trojan'));
    const bothOut = allowVless && allowTrojan;
    if (allowVless) {
      outbounds.push({
        type: 'vless',
        tag: n.name + (bothOut ? '-vless' : ''),
        server: n.addr,
        server_port: n.port,
        uuid,
        flow: '',
        tls: { enabled: true, server_name: sni, insecure: false },
        transport: { type: 'ws', path: wsPath, headers: { Host: wsHost } },
      });
    }
    if (allowTrojan) {
      outbounds.push({
        type: 'trojan',
        tag: n.name + (bothOut ? '-trojan' : ''),
        server: n.addr,
        server_port: n.port,
        password: uuid,
        tls: { enabled: true, server_name: sni, insecure: false },
        transport: { type: 'ws', path: (opts.trojanPath || '/trojan'), headers: { Host: wsHost } },
      });
    }
  }
  if (outbounds.length === 0) {
    // 兜底: 节点协议全被过滤, 给 vless
    for (const n of nodes) {
      outbounds.push({
        type: 'vless', tag: n.name,
        server: n.addr, server_port: n.port, uuid, flow: '',
        tls: { enabled: true, server_name: sni, insecure: false },
        transport: { type: 'ws', path: wsPath, headers: { Host: wsHost } },
      });
    }
  }
  const tags = outbounds.map(o => o.tag);
  const config = {
    log: { level: 'info' },
    dns: { servers: [{ address: '8.8.8.8', detour: 'select' }] },
    inbounds: [
      { type: 'tun', tag: 'tun-in', inet4_address: '172.19.0.1/30', auto_route: true, stack: 'system', sniff: true },
    ],
    outbounds: [
      { type: 'selector', tag: 'select', outbounds: ['auto', ...tags], default: 'auto' },
      { type: 'urltest', tag: 'auto', outbounds: tags, url: 'http://www.gstatic.com/generate_204', interval: '5m' },
      ...outbounds,
      { type: 'direct', tag: 'direct' },
    ],
    route: { final: 'select' },
  };
  return JSON.stringify(config, null, 2);
}

function buildSubUserInfo(u) {
  const used = u.total_used_bytes || 0;
  const total = u.total_quota_bytes || 0;
  let expire = 0;
  if (u.expire_at) expire = Math.floor(new Date(u.expire_at).getTime() / 1000);
  return `upload=0; download=${used}; total=${total}; expire=${expire}`;
}

// ========================================================================
// 7b. 客户美化页 /p/{uuid}  —— 手机浏览器打开, QR + 一键导入
// ========================================================================
async function handlePublicPage(request, env, url) {
  const uuid = url.pathname.slice('/p/'.length).replace(/\/$/, '');
  if (!uuid) return new Response('missing uuid', { status: 400 });

  const row = await env.DB.prepare(
    `SELECT uuid, email, enabled, expire_at,
            total_quota_bytes, total_used_bytes,
            daily_quota_bytes, daily_used_bytes
     FROM users WHERE uuid = ?`
  ).bind(uuid).first();
  if (!row) return new Response('node not found', { status: 404 });

  const settings = await getAllSettings(env).catch(() => ({}));
  const brand = settings.NODE_NAME_PREFIX || 'xiaox';
  const origin = url.origin;
  const subUrl = `${origin}/sub/${uuid}`;

  // 当前启用协议 (只为展示; 订阅里已经自动包含了)
  const enabledProtos = (settings.ENABLED_PROTOCOLS || 'vless')
    .split(/[,\s]+/).map(s => s.trim().toLowerCase()).filter(Boolean);
  const protoLabel = enabledProtos.map(p => p === 'vless' ? 'VLESS' : p === 'trojan' ? 'Trojan' : p.toUpperCase()).join(' + ') || 'VLESS';

  // 各客户端 scheme
  const encSub = encodeURIComponent(subUrl);
  const clashUrl    = `clash://install-config?url=${encSub}&name=${encodeURIComponent(brand)}`;
  const singboxUrl  = `sing-box://import-remote-profile?url=${encSub}#${encodeURIComponent(brand)}`;
  // Shadowrocket: sub://base64(url) 或 shadowrocket://add/sub://base64
  const srB64 = btoa(subUrl).replace(/=+$/, '');
  const shadowrocketUrl = `shadowrocket://add/sub://${srB64}`;
  const surgeUrl = `surge:///install-config?url=${encSub}&name=${encodeURIComponent(brand)}`;

  const usedPct = row.total_quota_bytes > 0
    ? Math.min(100, (row.total_used_bytes / row.total_quota_bytes) * 100) : 0;
  const dailyPct = row.daily_quota_bytes > 0
    ? Math.min(100, (row.daily_used_bytes / row.daily_quota_bytes) * 100) : 0;
  const expired = row.expire_at && new Date(row.expire_at) < new Date();
  const daysLeft = row.expire_at
    ? Math.max(0, Math.ceil((new Date(row.expire_at).getTime() - Date.now()) / 86400000))
    : null;

  const status = !row.enabled ? { label: '已禁用', cls: 'err' }
    : expired ? { label: '已过期', cls: 'err' }
    : daysLeft !== null && daysLeft <= 7 ? { label: `${daysLeft} 天后到期`, cls: 'warn' }
    : { label: '正常', cls: 'ok' };

  const html = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="dark light">
<title>${escapeHtml(brand)} · 我的节点</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; -webkit-tap-highlight-color: transparent; }
body { font-family: -apple-system, "PingFang SC", "Segoe UI", Roboto, sans-serif;
       background: linear-gradient(180deg, #0f1117 0%, #151823 100%); color: #e6e6e6;
       min-height: 100vh; padding: max(16px, env(safe-area-inset-top)) 16px env(safe-area-inset-bottom); }
.wrap { max-width: 500px; margin: 0 auto; }
h1 { font-size: 22px; margin: 24px 0 6px; font-weight: 600; }
.muted { color: #8b8fa5; font-size: 13px; }
.card { background: #1a1d26; border: 1px solid #262a35; border-radius: 14px; padding: 18px; margin-bottom: 14px; }
.row { display: flex; justify-content: space-between; align-items: center; gap: 10px; }
.row + .row { margin-top: 14px; }
.bar { background: #262a35; height: 6px; border-radius: 3px; overflow: hidden; margin-top: 6px; }
.bar-fill { height: 100%; background: #3b82f6; transition: width .2s; }
.bar-fill.warn { background: #f59e0b; }
.bar-fill.err  { background: #ef4444; }
.badge { display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 12px; font-weight: 500; }
.badge.ok   { background: #064e3b; color: #6ee7b7; }
.badge.warn { background: #78350f; color: #fcd34d; }
.badge.err  { background: #7f1d1d; color: #fca5a5; }
.big-btn { display: flex; align-items: center; gap: 14px; width: 100%; padding: 14px 16px;
           background: #3b82f6; color: #fff; border: 0; border-radius: 12px; font-size: 15px;
           font-weight: 500; text-decoration: none; margin-bottom: 10px; cursor: pointer; }
.big-btn:active { opacity: .85; }
.big-btn .ic { font-size: 22px; }
.big-btn.ghost { background: #262a35; color: #e6e6e6; }
.big-btn .sub { font-size: 11px; opacity: .7; margin-top: 2px; }
.big-btn .col { display: flex; flex-direction: column; align-items: flex-start; flex: 1; }
.url-box { background: #0f1117; border: 1px solid #262a35; border-radius: 8px;
           padding: 10px 12px; font-size: 12px; word-break: break-all; font-family: ui-monospace, Menlo, monospace;
           color: #9aa0a6; margin-top: 8px; }
.copy-btn { background: #262a35; color: #e6e6e6; border: 0; padding: 8px 14px;
            border-radius: 6px; font-size: 12px; font-weight: 500; cursor: pointer; }
.copy-btn:active { background: #3b82f6; }
#qr { display: flex; justify-content: center; padding: 18px; background: #fff; border-radius: 12px; margin-top: 10px; }
.footer { text-align: center; color: #6b7280; font-size: 12px; margin: 24px 0 40px; }
.toast { position: fixed; bottom: 30px; left: 50%; transform: translateX(-50%) translateY(80px);
         background: #1a1d26; border: 1px solid #3b82f6; padding: 10px 18px; border-radius: 22px;
         font-size: 13px; opacity: 0; transition: all .25s; z-index: 100; }
.toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }
h2 { font-size: 14px; color: #9aa0a6; font-weight: 500; margin-bottom: 10px; letter-spacing: .5px; text-transform: uppercase; }
.hint { font-size: 12px; color: #6b7280; margin-top: 8px; line-height: 1.5; }
</style>
</head>
<body>
<div class="wrap">

  <h1>${escapeHtml(brand)}</h1>
  <p class="muted">账号 ${escapeHtml(row.email || uuid.slice(0,8))}</p>

  <div class="card" style="margin-top: 16px">
    <div class="row">
      <div>
        <div class="muted" style="font-size:12px">状态</div>
        <div style="margin-top:4px"><span class="badge ${status.cls}">${status.label}</span></div>
      </div>
      <div style="text-align:center">
        <div class="muted" style="font-size:12px">协议</div>
        <div style="margin-top:4px;font-weight:500;font-size:13px">${escapeHtml(protoLabel)}</div>
      </div>
      <div style="text-align:right">
        <div class="muted" style="font-size:12px">到期</div>
        <div style="margin-top:4px;font-weight:500">${row.expire_at ? new Date(row.expire_at).toISOString().slice(0,10) : '∞'}</div>
      </div>
    </div>
    <div class="row" style="flex-direction:column;align-items:stretch">
      <div style="display:flex;justify-content:space-between;font-size:12px">
        <span class="muted">总流量</span>
        <span>${fmtBytesServer(row.total_used_bytes)} / ${row.total_quota_bytes ? fmtBytesServer(row.total_quota_bytes) : '∞'}</span>
      </div>
      <div class="bar"><div class="bar-fill ${usedPct>95?'err':usedPct>80?'warn':''}" style="width:${usedPct}%"></div></div>
    </div>
    ${row.daily_quota_bytes ? `
    <div class="row" style="flex-direction:column;align-items:stretch">
      <div style="display:flex;justify-content:space-between;font-size:12px">
        <span class="muted">今日</span>
        <span>${fmtBytesServer(row.daily_used_bytes)} / ${fmtBytesServer(row.daily_quota_bytes)}</span>
      </div>
      <div class="bar"><div class="bar-fill ${dailyPct>95?'err':dailyPct>80?'warn':''}" style="width:${dailyPct}%"></div></div>
    </div>` : ''}
  </div>

  <div class="card">
    <h2>一键导入</h2>
    <a class="big-btn" href="${clashUrl}">
      <span class="ic">🟢</span>
      <span class="col"><span>Clash / Clash Meta / Stash</span><span class="sub">Android / Windows / Mac / iOS</span></span>
    </a>
    <a class="big-btn ghost" href="${singboxUrl}">
      <span class="ic">📦</span>
      <span class="col"><span>Sing-box (SFA / SFI / SFM)</span><span class="sub">Android / iOS / Mac</span></span>
    </a>
    <a class="big-btn ghost" href="${shadowrocketUrl}">
      <span class="ic">🚀</span>
      <span class="col"><span>Shadowrocket</span><span class="sub">iOS</span></span>
    </a>
    <a class="big-btn ghost" href="${surgeUrl}">
      <span class="ic">⚡</span>
      <span class="col"><span>Surge</span><span class="sub">iOS / Mac</span></span>
    </a>
    <div class="hint">点按钮未跳转？说明你手机上没装对应 App。先到 App Store / Play Store 装好再回来。</div>
  </div>

  <div class="card">
    <h2>扫码导入</h2>
    <div id="qr"></div>
    <div class="hint">用另一台设备的客户端扫描，大部分 App（Clash/Shadowrocket/Sing-box）都支持"扫码添加订阅"。</div>
  </div>

  <div class="card">
    <h2>订阅 URL（手动粘贴）</h2>
    <div class="url-box" id="sub-url">${escapeHtml(subUrl)}</div>
    <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">
      <button class="copy-btn" data-copy="${escapeHtml(subUrl)}">复制通用订阅</button>
      <button class="copy-btn" data-copy="${escapeHtml(subUrl)}?sub=clash">复制 Clash 专用</button>
      <button class="copy-btn" data-copy="${escapeHtml(subUrl)}?sub=singbox">复制 Sing-box 专用</button>
    </div>
    <div class="hint">发给朋友时推荐发本页链接（${escapeHtml(origin)}/p/${uuid.slice(0,8)}…），他在手机浏览器打开点按钮就行。</div>
  </div>

  <div class="footer">powered by ${escapeHtml(brand)} · Cloudflare edge network</div>

</div>

<div id="toast" class="toast"></div>

<script src="https://cdn.jsdelivr.net/npm/qrcode@1.5.4/build/qrcode.min.js"></script>
<script>
// QR
const subUrl = ${JSON.stringify(subUrl)};
if (typeof QRCode !== 'undefined') {
  QRCode.toCanvas(subUrl, { width: 200, margin: 1, color: { dark: '#0f1117', light: '#ffffff' }}, (err, canvas) => {
    if (canvas) document.getElementById('qr').appendChild(canvas);
  });
} else {
  document.getElementById('qr').innerHTML = '<div style="color:#6b7280;font-size:12px">QR 库加载失败，请手动复制订阅 URL</div>';
}

// 复制
function toast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg; t.classList.add('show');
  clearTimeout(window._tt);
  window._tt = setTimeout(() => t.classList.remove('show'), 1800);
}
document.querySelectorAll('[data-copy]').forEach(el => {
  el.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(el.dataset.copy); toast('✓ 已复制'); }
    catch { toast('复制失败，请手动长按选择'); }
  });
});
</script>
</body>
</html>`;

  return new Response(html, { headers: { 'content-type': 'text/html; charset=utf-8' } });
}

function fmtBytesServer(b) {
  if (!b) return '0';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return (b < 10 ? b.toFixed(1) : Math.round(b)) + ' ' + u[i];
}

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

// ========================================================================
// 8. 管理 API
// ========================================================================

async function handleAdmin(request, env, url, ctx) {
  const auth = request.headers.get('authorization') || '';
  if (auth !== `Bearer ${env.ADMIN_TOKEN}`) {
    return new Response('unauthorized', { status: 401 });
  }

  if (url.pathname === '/admin/health') {
    const state = await env.DB.prepare(`SELECT key, value, updated_at FROM node_state`).all();
    const userCount = await env.DB.prepare(`SELECT COUNT(*) as n FROM users WHERE enabled=1`).first();
    const pendingPush = await env.DB.prepare(
      `SELECT COUNT(*) as n FROM traffic_buffer WHERE up_bytes>0 OR down_bytes>0`
    ).first();
    return json({
      ok: true,
      users_enabled: userCount?.n ?? 0,
      traffic_buffer_pending: pendingPush?.n ?? 0,
      panel_configured: !!(env.PANEL_URL && env.PANEL_TOKEN),
      state: state.results,
    });
  }

  if (url.pathname === '/admin/sync-now') {
    const [pullR, pushR] = await Promise.all([pullUsersFromPanel(env), pushTrafficToPanel(env)]);
    return json({ ok: true, pull: pullR, push: pushR });
  }

  // --- 节点预览: 返回当前筛选规则下的节点列表 (按地区分组统计) ---
  if (url.pathname === '/admin/preview-nodes' && request.method === 'GET') {
    try {
      const settings = await getAllSettings(env);
      const prefix = settings.NODE_NAME_PREFIX || 'node';
      // 本地 ADDRESSES
      const addrLines = (settings.ADDRESSES || '').split(/\r?\n/).map(s => s.trim()).filter(l => l && !l.startsWith('#'));
      let nodes = [];
      addrLines.forEach((line, i) => {
        const n = parseNodeLine(line, `${prefix}-${i + 1}`, 'local');
        if (n) nodes.push(n);
      });
      // 拉取优选 (可能为空/失败)
      try {
        const optimized = await fetchOptimizedAddresses(env, settings);
        optimized.forEach((n, i) => {
          nodes.push({ ...n, name: `${prefix}-优选-${i + 1}-${n.name}`.slice(0, 48) });
        });
      } catch {}
      const total_before = nodes.length;
      const filter = parseNodeFilter(settings.NODE_FILTER);
      // 可选 URL 覆盖 (方便管理端实时 preview 不同筛选)
      const overrideRegions = (url.searchParams.get('region') || '').split(',').map(s => s.trim()).filter(Boolean);
      const overrideTags    = (url.searchParams.get('tag')    || '').split(',').map(s => s.trim()).filter(Boolean);
      const overrides = { regions: overrideRegions, tags: overrideTags };
      const after = applyNodeFilter(nodes, filter, overrides);
      // 按 region 分组统计
      const byRegion = {};
      for (const n of after) {
        const r = (n.region || 'auto').toLowerCase();
        byRegion[r] = (byRegion[r] || 0) + 1;
      }
      // 只返回前 100 个节点, 避免前端爆炸
      return json({
        ok: true,
        total_before,
        total_after: after.length,
        by_region: byRegion,
        filter,
        nodes: after.slice(0, 100).map(n => ({
          addr: n.addr, port: n.port, name: n.name,
          region: n.region, tags: n.tags, protos: n.protos, source: n.source,
        })),
      });
    } catch (e) {
      return json({ ok: false, error: e.message }, 500);
    }
  }

  // --- 节点设置 ---
  if (url.pathname === '/admin/settings' && request.method === 'GET') {
    // 如果 settings 表不存在则返回空 (兼容老数据库)
    try {
      const s = await getAllSettings(env);
      return json({ ok: true, settings: s });
    } catch (e) {
      return json({ ok: true, settings: {}, warn: 'settings table missing, run migration' });
    }
  }

  if (url.pathname === '/admin/settings' && request.method === 'POST') {
    const body = await request.json().catch(() => ({}));
    if (!body || typeof body !== 'object') return json({ ok: false, error: 'invalid body' }, 400);
    try {
      for (const [k, v] of Object.entries(body)) {
        await setSetting(env, k, String(v ?? ''));
      }
      return json({ ok: true, settings: await getAllSettings(env) });
    } catch (e) {
      return json({ ok: false, error: e.message }, 500);
    }
  }

  if (url.pathname === '/admin/user' && request.method === 'GET') {
    const uuid = url.searchParams.get('uuid');
    if (!uuid) return json({ ok: false, error: 'missing uuid' }, 400);
    const row = await env.DB.prepare(`SELECT * FROM users WHERE uuid=?`).bind(uuid).first();
    return json({ ok: true, user: row });
  }

  if (url.pathname === '/admin/users' && request.method === 'GET') {
    const rows = await env.DB.prepare(
      `SELECT uuid, email, enabled, total_quota_bytes, total_used_bytes,
              daily_quota_bytes, daily_used_bytes, expire_at
       FROM users ORDER BY updated_at DESC`
    ).all();
    return json({ ok: true, users: rows.results });
  }

  if (url.pathname === '/admin/user' && request.method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const uuid = body.uuid || crypto.randomUUID();
    const GB = 1024 * 1024 * 1024;
    const daily = Math.floor((body.daily_quota_gb ?? 0) * GB);
    const total = Math.floor((body.total_quota_gb ?? 0) * GB);
    const expire = body.expire_days
      ? new Date(Date.now() + body.expire_days * 86400 * 1000).toISOString()
      : null;
    const enabled = body.enabled === false ? 0 : 1;
    const now = new Date().toISOString();

    await env.DB.prepare(
      `INSERT INTO users (uuid, panel_user_id, email, enabled,
         total_quota_bytes, daily_quota_bytes, expire_at, updated_at)
       VALUES (?, 0, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(uuid) DO UPDATE SET
         email = excluded.email, enabled = excluded.enabled,
         total_quota_bytes = excluded.total_quota_bytes,
         daily_quota_bytes = excluded.daily_quota_bytes,
         expire_at = excluded.expire_at, updated_at = excluded.updated_at`
    ).bind(uuid, body.email || null, enabled, total, daily, expire, now).run();

    await env.KV.delete('user:' + uuid);
    await env.KV.delete('block:' + uuid);
    await env.KV.delete('trojan_map');  // 用户变更, 重建 Trojan hash → uuid 映射

    return json({ ok: true, uuid, email: body.email,
                  daily_quota_gb: body.daily_quota_gb,
                  total_quota_gb: body.total_quota_gb, expire_at: expire });
  }

  if (url.pathname === '/admin/user' && request.method === 'DELETE') {
    const uuid = url.searchParams.get('uuid');
    if (!uuid) return json({ ok: false, error: 'missing uuid' }, 400);
    await env.DB.prepare(`DELETE FROM users WHERE uuid=?`).bind(uuid).run();
    await env.DB.prepare(`DELETE FROM traffic_buffer WHERE uuid=?`).bind(uuid).run();
    await env.KV.delete('user:' + uuid);
    await env.KV.delete('block:' + uuid);
    await env.KV.delete('trojan_map');
    return json({ ok: true });
  }

  if (url.pathname === '/admin/unblock' && request.method === 'POST') {
    const uuid = url.searchParams.get('uuid');
    if (!uuid) return json({ ok: false, error: 'missing uuid' }, 400);
    await env.KV.delete('block:' + uuid);
    await env.KV.delete('user:' + uuid);
    return json({ ok: true });
  }

  if (url.pathname === '/admin/reset-daily' && request.method === 'POST') {
    const uuid = url.searchParams.get('uuid');
    const now = new Date().toISOString();
    if (uuid) {
      await env.DB.prepare(`UPDATE users SET daily_used_bytes=0, daily_reset_at=? WHERE uuid=?`).bind(now, uuid).run();
      await env.KV.delete('block:' + uuid);
      await env.KV.delete('user:' + uuid);
    } else {
      await env.DB.prepare(`UPDATE users SET daily_used_bytes=0, daily_reset_at=?`).bind(now).run();
    }
    return json({ ok: true });
  }

  // --- 启用/停用单用户 ---
  if (url.pathname === '/admin/user/toggle' && request.method === 'POST') {
    const uuid = url.searchParams.get('uuid');
    if (!uuid) return json({ ok: false, error: 'missing uuid' }, 400);
    const row = await env.DB.prepare(`SELECT enabled FROM users WHERE uuid=?`).bind(uuid).first();
    if (!row) return json({ ok: false, error: 'user not found' }, 404);
    const next = row.enabled ? 0 : 1;
    await env.DB.prepare(`UPDATE users SET enabled=?, updated_at=? WHERE uuid=?`)
      .bind(next, new Date().toISOString(), uuid).run();
    await env.KV.delete('user:' + uuid);
    return json({ ok: true, enabled: !!next });
  }

  // --- 延期 N 天 (在当前 expire_at 和 now 之间取较大者, 再 +N 天) ---
  if (url.pathname === '/admin/user/extend' && request.method === 'POST') {
    const uuid = url.searchParams.get('uuid');
    const days = Number(url.searchParams.get('days')) || 0;
    if (!uuid || !days) return json({ ok: false, error: 'missing uuid or days' }, 400);
    const row = await env.DB.prepare(`SELECT expire_at FROM users WHERE uuid=?`).bind(uuid).first();
    if (!row) return json({ ok: false, error: 'user not found' }, 404);
    const base = row.expire_at && new Date(row.expire_at) > new Date()
      ? new Date(row.expire_at)
      : new Date();
    const next = new Date(base.getTime() + days * 86400 * 1000).toISOString();
    await env.DB.prepare(`UPDATE users SET expire_at=?, updated_at=? WHERE uuid=?`)
      .bind(next, new Date().toISOString(), uuid).run();
    await env.KV.delete('user:' + uuid);
    return json({ ok: true, expire_at: next });
  }

  // --- 重置总流量(保留额度不变) ---
  if (url.pathname === '/admin/user/reset-total' && request.method === 'POST') {
    const uuid = url.searchParams.get('uuid');
    if (!uuid) return json({ ok: false, error: 'missing uuid' }, 400);
    await env.DB.prepare(`UPDATE users SET total_used_bytes=0, updated_at=? WHERE uuid=?`)
      .bind(new Date().toISOString(), uuid).run();
    await env.DB.prepare(`UPDATE traffic_buffer SET up_bytes=0, down_bytes=0 WHERE uuid=?`).bind(uuid).run();
    await env.KV.delete('user:' + uuid);
    await env.KV.delete('block:' + uuid);
    return json({ ok: true });
  }

  // --- 编辑用户额度/有效期(整表覆盖, 用于"改套餐"场景) ---
  if (url.pathname === '/admin/user/edit' && request.method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const uuid = body.uuid;
    if (!uuid) return json({ ok: false, error: 'missing uuid' }, 400);
    const row = await env.DB.prepare(`SELECT * FROM users WHERE uuid=?`).bind(uuid).first();
    if (!row) return json({ ok: false, error: 'user not found' }, 404);
    const GB = 1024 * 1024 * 1024;
    const next = {
      email: body.email ?? row.email,
      daily_quota_bytes: body.daily_quota_gb != null ? Math.floor(body.daily_quota_gb * GB) : row.daily_quota_bytes,
      total_quota_bytes: body.total_quota_gb != null ? Math.floor(body.total_quota_gb * GB) : row.total_quota_bytes,
      expire_at: body.expire_at !== undefined ? body.expire_at : row.expire_at,
    };
    await env.DB.prepare(
      `UPDATE users SET email=?, daily_quota_bytes=?, total_quota_bytes=?, expire_at=?, updated_at=? WHERE uuid=?`
    ).bind(next.email, next.daily_quota_bytes, next.total_quota_bytes, next.expire_at,
           new Date().toISOString(), uuid).run();
    await env.KV.delete('user:' + uuid);
    return json({ ok: true });
  }

  // --- 聚合当前节点池可用的 tag / region (UI 从这里拿数据做 chip) ---
  if (url.pathname === '/admin/node-facets' && request.method === 'GET') {
    try {
      const settings = await getAllSettings(env);
      const prefix = settings.NODE_NAME_PREFIX || 'node';
      const addrLines = (settings.ADDRESSES || '').split(/\r?\n/).map(s => s.trim()).filter(l => l && !l.startsWith('#'));
      const nodes = [];
      addrLines.forEach((line, i) => {
        const n = parseNodeLine(line, `${prefix}-${i + 1}`, 'local');
        if (n) nodes.push(n);
      });
      try {
        const optimized = await fetchOptimizedAddresses(env, settings);
        optimized.forEach(n => nodes.push(n));
      } catch {}
      const regionCnt = {}, tagCnt = {};
      for (const n of nodes) {
        const r = (n.region || 'auto').toLowerCase();
        regionCnt[r] = (regionCnt[r] || 0) + 1;
        for (const t of (n.tags || [])) tagCnt[t] = (tagCnt[t] || 0) + 1;
      }
      return json({
        ok: true,
        total: nodes.length,
        regions: Object.entries(regionCnt).sort((a,b) => b[1]-a[1]).map(([k,v]) => ({ k, n: v })),
        tags:    Object.entries(tagCnt).sort((a,b) => b[1]-a[1]).map(([k,v]) => ({ k, n: v })),
      });
    } catch (e) {
      return json({ ok: false, error: e.message }, 500);
    }
  }

  return new Response('not found', { status: 404 });
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), {
    status, headers: { 'content-type': 'application/json' }
  });
}

// ========================================================================
// 9. 工具
// ========================================================================

function makeReadableWebSocketStream(ws, earlyDataHeader) {
  let readableStreamCancel = false;
  return new ReadableStream({
    start(controller) {
      ws.addEventListener('message', e => {
        if (readableStreamCancel) return;
        controller.enqueue(e.data);
      });
      ws.addEventListener('close', () => {
        safeCloseWS(ws);
        if (!readableStreamCancel) controller.close();
      });
      ws.addEventListener('error', e => controller.error(e));
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) controller.error(error);
      else if (earlyData) controller.enqueue(earlyData);
    },
    cancel() { readableStreamCancel = true; safeCloseWS(ws); }
  });
}

function base64ToArrayBuffer(s) {
  if (!s) return { earlyData: null, error: null };
  try {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(s);
    const buf = Uint8Array.from(bin, c => c.charCodeAt(0));
    return { earlyData: buf.buffer, error: null };
  } catch (e) { return { earlyData: null, error: e }; }
}

function safeCloseWS(ws, code, reason) {
  try { if (ws.readyState === 1 || ws.readyState === 2) ws.close(code, reason); } catch {}
}

const HEX = Array.from({ length: 256 }, (_, i) => (i + 256).toString(16).slice(1));
function stringifyUUID(arr, offset = 0) {
  return (
    HEX[arr[offset + 0]] + HEX[arr[offset + 1]] + HEX[arr[offset + 2]] + HEX[arr[offset + 3]] + '-' +
    HEX[arr[offset + 4]] + HEX[arr[offset + 5]] + '-' +
    HEX[arr[offset + 6]] + HEX[arr[offset + 7]] + '-' +
    HEX[arr[offset + 8]] + HEX[arr[offset + 9]] + '-' +
    HEX[arr[offset + 10]] + HEX[arr[offset + 11]] + HEX[arr[offset + 12]] +
    HEX[arr[offset + 13]] + HEX[arr[offset + 14]] + HEX[arr[offset + 15]]
  ).toLowerCase();
}

// ========================================================================
// 10. 内置管理 UI（HTML + Vanilla JS）
// ========================================================================

const ADMIN_HTML = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>节点管理</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, "Segoe UI", Roboto, "PingFang SC", sans-serif;
       background: #0f1117; color: #e6e6e6; font-size: 14px; min-height: 100vh; }
.wrap { max-width: 1100px; margin: 0 auto; padding: 24px 20px; }
.card { background: #1a1d26; border: 1px solid #262a35; border-radius: 10px; padding: 20px; margin-bottom: 16px; }
h1 { font-size: 20px; margin-bottom: 16px; }
h2 { font-size: 16px; margin-bottom: 12px; color: #9aa0a6; font-weight: 500; }
button { background: #3b82f6; color: #fff; border: 0; padding: 8px 16px; border-radius: 6px;
         cursor: pointer; font-size: 13px; font-weight: 500; }
button:hover { background: #2563eb; }
button.ghost { background: transparent; color: #9aa0a6; border: 1px solid #2a2e3a; }
button.ghost:hover { background: #262a35; color: #e6e6e6; }
button.danger { background: #ef4444; }
button.danger:hover { background: #dc2626; }
button.small { padding: 4px 10px; font-size: 12px; }
input, select { background: #0f1117; color: #e6e6e6; border: 1px solid #2a2e3a;
                padding: 8px 10px; border-radius: 6px; font-size: 13px; width: 100%; font-family: inherit; }
input:focus { outline: none; border-color: #3b82f6; }
label { display: block; margin-bottom: 6px; color: #9aa0a6; font-size: 12px; }
.row { display: flex; gap: 12px; flex-wrap: wrap; }
.row > * { flex: 1; min-width: 150px; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 10px 8px; border-bottom: 1px solid #262a35; font-size: 13px; }
th { color: #9aa0a6; font-weight: 500; font-size: 12px; text-transform: uppercase; }
td.actions { white-space: nowrap; }
td.actions button { margin-right: 4px; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: 500; }
.badge.ok { background: #064e3b; color: #6ee7b7; }
.badge.warn { background: #78350f; color: #fcd34d; }
.badge.err { background: #7f1d1d; color: #fca5a5; }
.bar { background: #262a35; height: 4px; border-radius: 2px; overflow: hidden; margin-top: 3px; }
.bar-fill { height: 100%; background: #3b82f6; transition: width .2s; }
.bar-fill.warn { background: #f59e0b; }
.bar-fill.err { background: #ef4444; }
.muted { color: #6b7280; font-size: 12px; }
.stat { display: flex; gap: 20px; margin-bottom: 16px; }
.stat > div { flex: 1; background: #1a1d26; border: 1px solid #262a35; border-radius: 10px; padding: 16px; }
.stat .v { font-size: 22px; font-weight: 600; }
.stat .l { font-size: 12px; color: #9aa0a6; margin-top: 4px; }
.modal { position: fixed; inset: 0; background: rgba(0,0,0,.7); display: none;
         align-items: center; justify-content: center; z-index: 10; padding: 20px; }
.modal.show { display: flex; }
.modal-inner { background: #1a1d26; border: 1px solid #262a35; border-radius: 10px;
               padding: 24px; width: 100%; max-width: 480px; }
.toast { position: fixed; bottom: 24px; right: 24px; background: #1a1d26;
         border: 1px solid #3b82f6; padding: 12px 16px; border-radius: 8px; z-index: 20;
         transform: translateY(100px); opacity: 0; transition: all .25s; }
.toast.show { transform: translateY(0); opacity: 1; }
.preset { display: flex; gap: 8px; margin-bottom: 14px; flex-wrap: wrap; }
.preset button { background: #262a35; color: #e6e6e6; }
.preset button:hover { background: #3b82f6; }
#login-screen { max-width: 360px; margin: 80px auto; }
.tabs { display: flex; gap: 4px; border-bottom: 1px solid #262a35; margin-bottom: 16px; }
.tabs button { background: transparent; color: #9aa0a6; border: 0; padding: 10px 16px; border-radius: 0;
               border-bottom: 2px solid transparent; font-size: 14px; }
.tabs button.active { color: #e6e6e6; border-bottom-color: #3b82f6; background: transparent; }
textarea { background: #0f1117; color: #e6e6e6; border: 1px solid #2a2e3a;
           padding: 8px 10px; border-radius: 6px; font-size: 13px; width: 100%; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; resize: vertical; min-height: 140px; }
textarea:focus { outline: none; border-color: #3b82f6; }
.hint { font-size: 12px; color: #6b7280; margin-top: 4px; line-height: 1.5; }
.kv { display: grid; grid-template-columns: 140px 1fr; gap: 10px 14px; align-items: start; }
.kv label { line-height: 34px; margin: 0; }

/* ------- 点选卡片: 套餐预设 ------- */
.plan-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px; margin-bottom: 16px; }
.plan-card { background: #0f1117; border: 2px solid #2a2e3a; border-radius: 10px; padding: 14px 12px;
             cursor: pointer; transition: all .15s; text-align: center; }
.plan-card:hover { border-color: #3b82f6; background: #131724; }
.plan-card.active { border-color: #3b82f6; background: #172033; box-shadow: 0 0 0 2px rgba(59,130,246,.15); }
.plan-card .pt { font-size: 14px; font-weight: 600; color: #e6e6e6; }
.plan-card .pv { font-size: 18px; font-weight: 700; color: #7fb3ff; margin: 6px 0; }
.plan-card .ps { font-size: 11px; color: #6b7280; }

/* ------- Chip: 地区/标签可点选 ------- */
.chips { display: flex; flex-wrap: wrap; gap: 6px; padding: 6px 0; }
.chip { display: inline-flex; align-items: center; gap: 4px; background: #0f1117; border: 1px solid #2a2e3a;
        padding: 4px 10px; border-radius: 20px; font-size: 12px; color: #9aa0a6; cursor: pointer;
        user-select: none; transition: all .15s; }
.chip:hover { border-color: #3b82f6; color: #e6e6e6; }
.chip.active { background: #172033; border-color: #3b82f6; color: #7fb3ff; font-weight: 500; }
.chip.neg { border-color: #7f1d1d; color: #fca5a5; }
.chip.neg.active { background: #3d1111; border-color: #ef4444; color: #fca5a5; }
.chip .cnt { font-size: 10px; color: #6b7280; font-weight: 400; }

/* ------- 节点表格 ------- */
.node-tbl { width: 100%; border-collapse: separate; border-spacing: 0 4px; }
.node-tbl th { padding: 4px 6px; font-size: 11px; color: #6b7280; text-transform: none; }
.node-tbl td { padding: 0; border: 0; background: transparent; }
.node-tbl td input, .node-tbl td select { padding: 6px 8px; font-size: 12px; background: #0f1117; }
.node-tbl tr.node-row td:first-child input { border-radius: 6px 0 0 6px; }
.node-tbl tr.node-row td:last-child  { padding-left: 4px; }
.node-tbl .proto-cell { display: flex; gap: 8px; font-size: 11px; background: #0f1117;
                        padding: 5px 8px; border: 1px solid #2a2e3a; border-radius: 6px; }
.node-tbl .proto-cell label { display: flex; align-items: center; gap: 3px; margin: 0; font-size: 11px; color: #9aa0a6; cursor: pointer; }
.node-tbl .del-btn { background: transparent; border: 1px solid #3a1f2a; color: #ef4444; padding: 6px 8px; border-radius: 6px; font-size: 11px; }
.node-tbl .del-btn:hover { background: #3a1f2a; }
.node-tbl .src-badge { font-size: 10px; color: #6b7280; padding: 2px 6px; border: 1px solid #262a35; border-radius: 3px; }

/* ------- 优选源清单 ------- */
.src-list { display: flex; flex-direction: column; gap: 8px; }
.src-item { display: grid; grid-template-columns: 40px 1fr 110px 140px 28px; gap: 8px; align-items: center;
            background: #0f1117; border: 1px solid #2a2e3a; padding: 10px; border-radius: 8px; }
.src-item.off { opacity: .5; }
.src-item input, .src-item select { padding: 6px 8px; font-size: 12px; }
.src-item .sw { display: flex; justify-content: center; }
.src-item .name-row { display: flex; flex-direction: column; gap: 2px; }
.src-item .name-row .n { font-size: 13px; font-weight: 500; color: #e6e6e6; }
.src-item .name-row .u { font-size: 10px; color: #6b7280; font-family: ui-monospace, Menlo, monospace;
                         overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.sw-input { position: relative; width: 36px; height: 20px; cursor: pointer; appearance: none; background: #2a2e3a;
            border-radius: 10px; transition: .2s; border: 0; padding: 0; }
.sw-input::after { content: ''; position: absolute; left: 2px; top: 2px; width: 16px; height: 16px;
                   background: #fff; border-radius: 50%; transition: .2s; }
.sw-input:checked { background: #3b82f6; }
.sw-input:checked::after { left: 18px; }

/* ------- 数量限制按钮组 ------- */
.btn-group { display: inline-flex; gap: 4px; }
.btn-group button { background: #0f1117; border: 1px solid #2a2e3a; color: #9aa0a6;
                    padding: 6px 12px; font-size: 12px; border-radius: 6px; font-weight: 500; }
.btn-group button:hover { border-color: #3b82f6; color: #e6e6e6; }
.btn-group button.active { background: #172033; border-color: #3b82f6; color: #7fb3ff; }

/* ------- 操作下拉菜单 ------- */
.action-wrap { position: relative; display: inline-block; }
.action-menu { position: absolute; right: 0; top: calc(100% + 4px); background: #1a1d26; border: 1px solid #2a2e3a;
               border-radius: 8px; min-width: 170px; z-index: 30; padding: 4px; box-shadow: 0 8px 24px rgba(0,0,0,.4);
               display: none; }
.action-menu.show { display: block; }
.action-menu button { display: block; width: 100%; text-align: left; background: transparent; color: #e6e6e6;
                      padding: 8px 12px; border-radius: 4px; font-size: 12px; font-weight: 400; }
.action-menu button:hover { background: #262a35; }
.action-menu button.danger-item { color: #fca5a5; }
.action-menu button.danger-item:hover { background: #3a1f2a; }
.action-menu hr { border: 0; border-top: 1px solid #262a35; margin: 4px 0; }
</style>
</head>
<body>
<div id="app"></div>

<div id="login-screen" class="card" style="display:none">
  <h1>节点管理</h1>
  <label>管理员 Token</label>
  <input id="token-input" type="password" placeholder="ADMIN_TOKEN">
  <div style="margin-top:12px"><button id="login-btn" style="width:100%">登录</button></div>
  <div id="login-err" class="muted" style="margin-top:8px;color:#fca5a5"></div>
</div>

<div id="dashboard" style="display:none">
  <div class="wrap">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
      <h1>节点管理</h1>
      <button class="ghost small" id="logout-btn">退出</button>
    </div>

    <div class="stat">
      <div><div class="v" id="s-users">—</div><div class="l">启用用户</div></div>
      <div><div class="v" id="s-pending">—</div><div class="l">待上报流量条数</div></div>
      <div><div class="v" id="s-sync">—</div><div class="l">模式</div></div>
    </div>

    <div class="tabs">
      <button class="tab-btn active" data-tab="users">用户</button>
      <button class="tab-btn" data-tab="settings">节点设置</button>
    </div>

    <div id="pane-users" class="pane">
      <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
          <h2>用户列表</h2>
          <div>
            <button class="ghost small" id="refresh-btn">刷新</button>
            <button id="new-user-btn">+ 新建用户</button>
          </div>
        </div>
        <table>
          <thead><tr>
            <th>邮箱</th><th>UUID</th><th>今日</th><th>总量</th><th>到期</th><th>状态</th><th></th>
          </tr></thead>
          <tbody id="users-tbody"></tbody>
        </table>
      </div>
    </div>

    <div id="pane-settings" class="pane" style="display:none">
      <div class="card">
        <h2>节点设置</h2>
        <p class="hint" style="margin-bottom:14px">改完点右下角「保存」，立即生效（订阅端 60 秒内刷新）。</p>

        <div class="kv">
          <label>启用协议</label>
          <div>
            <div style="display:flex;gap:18px;flex-wrap:wrap;align-items:center;padding:8px 0">
              <label style="display:flex;align-items:center;gap:6px;margin:0;font-weight:500;cursor:pointer">
                <input type="checkbox" id="st-proto-vless" style="width:16px;height:16px;margin:0">
                <span>VLESS</span>
              </label>
              <label style="display:flex;align-items:center;gap:6px;margin:0;font-weight:500;cursor:pointer">
                <input type="checkbox" id="st-proto-trojan" style="width:16px;height:16px;margin:0">
                <span>Trojan</span>
              </label>
            </div>
            <div class="hint">选中的协议会同时在同一批节点上启用——每个节点自动生成两种协议的订阅条目，客户端选哪个用哪个。两个都不勾会默认启用 VLESS。</div>
          </div>

          <label>Trojan WS 路径</label>
          <div>
            <input id="st-TROJAN_PATH" placeholder="/trojan">
            <div class="hint">Trojan 协议走的 WebSocket path，必须和下面「VLESS WS 路径」不一样（Worker 靠 path 区分协议）。默认 <code>/trojan</code>，改完订阅里的 Trojan 节点会自动跟着改。</div>
          </div>

          <label>反代 IP (PROXYIP)</label>
          <div>
            <input id="st-PROXYIP" placeholder="空 = 不用反代, 例: cf.090227.xyz 或 1.2.3.4:443">
            <div class="hint">当 Cloudflare 被目标服务拉黑（如 TG/部分小众站）时，流量会自动兜底到这个 IP。可填 cmliu 的优选 <code>cf.090227.xyz</code> / <code>ProxyIP.US.CMLiussss.net</code>。</div>
          </div>

          <label>节点地址列表</label>
          <div>
            <!-- 表格 UI (默认) -->
            <div id="nodes-ui">
              <table class="node-tbl">
                <thead>
                  <tr>
                    <th style="width:28%">地址</th>
                    <th style="width:65px">端口</th>
                    <th style="width:16%">备注</th>
                    <th style="width:80px">地区</th>
                    <th>标签</th>
                    <th style="width:120px">协议</th>
                    <th style="width:34px"></th>
                  </tr>
                </thead>
                <tbody id="nodes-tbody"></tbody>
              </table>
              <div style="display:flex;gap:8px;margin-top:8px;align-items:center">
                <button class="small ghost" id="nodes-add">+ 添加一行</button>
                <button class="small ghost" id="nodes-add-preset">+ 常用节点模板</button>
                <span class="hint" style="margin:0 0 0 auto">高级: <a href="#" id="nodes-toggle-text" style="color:#7fb3ff;text-decoration:none">切到文本编辑</a></span>
              </div>
            </div>
            <!-- 文本 UI (隐藏备用) -->
            <div id="nodes-text" style="display:none">
              <textarea id="st-ADDRESSES"></textarea>
              <div style="display:flex;justify-content:flex-end;margin-top:6px">
                <a href="#" id="nodes-toggle-ui" style="color:#7fb3ff;text-decoration:none;font-size:12px">← 切回表格编辑</a>
              </div>
            </div>
            <div class="hint">每行一个节点，地区/标签/协议都用下拉选择，不用手写语法。留空就是默认，会参与「订阅筛选」时的全局池。</div>
          </div>

          <label>优选IP API (ADDAPI)</label>
          <div>
            <div id="addapi-ui" class="src-list"></div>
            <div style="display:flex;gap:8px;margin-top:8px;align-items:center">
              <button class="small ghost" id="addapi-add">+ 自定义源</button>
              <span class="hint" style="margin:0 0 0 auto">高级: <a href="#" id="addapi-toggle-text" style="color:#7fb3ff;text-decoration:none">切到文本编辑</a></span>
            </div>
            <div id="addapi-text" style="display:none;margin-top:8px">
              <textarea id="st-ADDAPI"></textarea>
              <div style="display:flex;justify-content:flex-end;margin-top:6px">
                <a href="#" id="addapi-toggle-ui" style="color:#7fb3ff;text-decoration:none;font-size:12px">← 切回清单</a>
              </div>
            </div>
            <div class="hint">勾选启用就会参与合成池。KV 缓存 10 分钟。地区/标签是给这批节点打的默认属性，方便后面筛。</div>
          </div>

          <label>优选IP CSV (ADDCSV)</label>
          <div>
            <input id="st-ADDCSV" placeholder="https://example.com/result.csv  (留空不启用)">
            <div class="hint">iptest 格式 CSV（表头 <code>ip,port,tls,colo,...</code>），只取 <code>tls=TRUE</code> 的行。自动按 <code>colo</code> 字段推断地区（LAX→us, HKG→hk, NRT→jp...），并加 <code>colo-XXX</code> 标签。</div>
          </div>

          <label>节点名前缀</label>
          <div>
            <input id="st-NODE_NAME_PREFIX" placeholder="xiaox">
            <div class="hint">如果某行没写 <code>#备注</code>，就用这个前缀自动命名（xiaox-1、xiaox-2...）。</div>
          </div>

          <label>VLESS WS 路径</label>
          <div>
            <input id="st-WS_PATH" placeholder="/">
            <div class="hint">VLESS 协议走的 WebSocket path。默认 <code>/</code>。想增加隐蔽度可改 <code>/api</code> <code>/xxx</code>。改了要所有订阅重新拉一次。</div>
          </div>

          <label>SOCKS5 (预留)</label>
          <div>
            <input id="st-SOCKS5" placeholder="user:pass@host:port" disabled>
            <div class="hint">上游 SOCKS5 代理，MVP 阶段未接入，留空即可。</div>
          </div>
        </div>

        <div style="margin-top:20px;display:flex;justify-content:flex-end;gap:8px">
          <button class="ghost" id="st-reload">重新读取</button>
          <button id="st-save">保存</button>
        </div>
      </div>

      <div class="card" style="margin-top:16px">
        <h2>订阅筛选</h2>
        <p class="hint" style="margin-bottom:14px">从上面「节点地址列表」+「优选IP」合成的节点池里，再次按地区/标签筛一刀。客户端订阅时生效，不影响节点本身的存储。</p>

        <div class="kv">
          <label>只保留地区</label>
          <div>
            <div id="f-regions-chips" class="chips"></div>
            <div class="hint">点击选中，再点取消。全部不选 = 保留所有地区。</div>
          </div>

          <label>排除地区</label>
          <div>
            <div id="f-exclude-regions-chips" class="chips"></div>
            <div class="hint">被选中的地区直接剔除。优先级高于「只保留地区」。</div>
          </div>

          <label>必须包含标签</label>
          <div>
            <div id="f-include-tags-chips" class="chips"></div>
            <div class="hint">从当前节点池里自动聚合出可用标签。节点至少带其中一个才保留。</div>
          </div>

          <label>排除标签</label>
          <div>
            <div id="f-exclude-tags-chips" class="chips"></div>
            <div class="hint">带任一被选中标签的节点直接剔除。</div>
          </div>

          <label>每地区最多</label>
          <div>
            <div class="btn-group" id="f-max-per-region-btns">
              <button type="button" data-v="0">不限</button>
              <button type="button" data-v="3">3</button>
              <button type="button" data-v="5">5</button>
              <button type="button" data-v="10">10</button>
              <button type="button" data-v="20">20</button>
            </div>
            <div class="hint">每个地区最多保留几个节点。</div>
          </div>

          <label>总数上限</label>
          <div>
            <div class="btn-group" id="f-total-max-btns">
              <button type="button" data-v="20">20</button>
              <button type="button" data-v="40">40</button>
              <button type="button" data-v="60">60</button>
              <button type="button" data-v="100">100</button>
              <button type="button" data-v="0">不限</button>
            </div>
            <div class="hint">筛完后最多留多少个节点。客户端节点列表太长会卡，一般 40-60 够用。</div>
          </div>
        </div>

        <div style="margin-top:20px;display:flex;justify-content:flex-end;gap:8px">
          <button class="ghost" id="st-f-preview">预览筛选结果</button>
          <button class="ghost" id="st-f-reload">重新读取</button>
          <button id="st-f-save">保存</button>
        </div>

        <div id="st-f-preview-result" style="margin-top:18px;display:none">
          <h3 style="margin:0 0 8px 0;font-size:14px;color:#a8bfe0">预览</h3>
          <div id="st-f-preview-summary" style="font-size:13px;color:#8ba3c7;margin-bottom:10px"></div>
          <div style="max-height:300px;overflow:auto;border:1px solid #1f2d4a;border-radius:8px">
            <table style="width:100%;font-size:12px">
              <thead style="background:#1b2942;position:sticky;top:0">
                <tr>
                  <th style="text-align:left;padding:6px 8px">地址</th>
                  <th style="text-align:left;padding:6px 8px">地区</th>
                  <th style="text-align:left;padding:6px 8px">标签</th>
                  <th style="text-align:left;padding:6px 8px">协议</th>
                  <th style="text-align:left;padding:6px 8px">源</th>
                </tr>
              </thead>
              <tbody id="st-f-preview-tbody"></tbody>
            </table>
          </div>
          <div class="hint" style="margin-top:6px">最多显示前 100 条。</div>
        </div>

        <details style="margin-top:14px">
          <summary style="cursor:pointer;color:#8ba3c7;font-size:13px">⚙ 用户端可用的 URL 参数（高级）</summary>
          <div class="hint" style="margin-top:8px;line-height:1.7">
            订阅链接后加参数可临时覆盖筛选，不改后台配置：<br>
            <code>?region=us,hk</code> — 临时只取美港<br>
            <code>?tag=premium</code> — 临时只取 premium 标签<br>
            <code>?limit=10</code> — 临时最多 10 个节点<br>
            <code>?proto=vless</code> 或 <code>?proto=trojan</code> — 临时只输出单协议<br>
            示例：<code>/sub/{uuid}?region=jp&limit=5</code>
          </div>
        </details>
      </div>
    </div>

  </div>
</div>

<div id="new-modal" class="modal">
  <div class="modal-inner" style="max-width:520px">
    <h1 style="font-size:18px;margin-bottom:6px">新建用户</h1>
    <p class="muted" style="margin-bottom:14px">点一个套餐卡片 → 填备注 → 创建。不用手填数字。</p>

    <label style="margin-bottom:8px">选择套餐</label>
    <div class="plan-cards" id="plan-cards">
      <div class="plan-card" data-plan="trial" data-total="5"  data-days="3"   data-daily="0">
        <div class="pt">体验</div><div class="pv">3 天</div><div class="ps">5 GB</div>
      </div>
      <div class="plan-card active" data-plan="monthly" data-total="100" data-days="30" data-daily="0">
        <div class="pt">月卡</div><div class="pv">30 天</div><div class="ps">100 GB</div>
      </div>
      <div class="plan-card" data-plan="quarterly" data-total="300" data-days="90" data-daily="0">
        <div class="pt">季卡</div><div class="pv">90 天</div><div class="ps">300 GB</div>
      </div>
      <div class="plan-card" data-plan="yearly" data-total="1024" data-days="365" data-daily="0">
        <div class="pt">年卡</div><div class="pv">365 天</div><div class="ps">1 TB</div>
      </div>
      <div class="plan-card" data-plan="unlimited" data-total="0" data-days="30" data-daily="0">
        <div class="pt">月不限流</div><div class="pv">30 天</div><div class="ps">不限额</div>
      </div>
      <div class="plan-card" data-plan="custom" data-total="" data-days="" data-daily="">
        <div class="pt">自定义</div><div class="pv">...</div><div class="ps">手动填</div>
      </div>
    </div>

    <div id="custom-fields" style="display:none;margin-bottom:14px">
      <div class="row">
        <div><label>每日限额 (GB, 0=不限)</label><input id="f-daily" type="number" value="0" step="0.1"></div>
        <div><label>总流量 (GB, 0=不限)</label><input id="f-total" type="number" value="100" step="0.1"></div>
        <div><label>有效期 (天, 0=永久)</label><input id="f-days" type="number" value="30"></div>
      </div>
    </div>

    <label>备注 / 客户昵称（可选）</label>
    <input id="f-email" placeholder="微信昵称 / 邮箱 / 任意标签">

    <div style="margin-top:20px;display:flex;gap:8px;justify-content:flex-end">
      <button class="ghost" id="new-cancel">取消</button>
      <button id="new-submit">创建并生成订阅</button>
    </div>
  </div>
</div>

<div id="sub-modal" class="modal">
  <div class="modal-inner" style="max-width:560px">
    <h1 style="font-size:18px;margin-bottom:8px">订阅链接</h1>

    <div style="background:#1b2942;border:1px solid #2a3f66;border-radius:10px;padding:12px 14px;margin-bottom:14px">
      <div style="font-size:12px;color:#7f9cc7;margin-bottom:6px">⭐ 推荐发给客户（手机打开就能一键导入）</div>
      <label style="margin-top:0">客户订阅页</label>
      <input id="sub-page" readonly style="background:#0f1a30;font-weight:600">
      <div style="margin-top:6px;display:flex;gap:6px;align-items:center">
        <button class="small" id="sub-copy-page">复制</button>
        <button class="small ghost" id="sub-open-page">在新标签打开</button>
        <span class="hint" style="margin-left:auto">带余额/到期 + 一键导入</span>
      </div>
    </div>

    <p class="muted" style="margin-bottom:12px">下面是原始订阅格式，高级用户手动导入用。</p>

    <label>通用订阅 (V2RayN / Shadowrocket / v2rayNG)</label>
    <input id="sub-url" readonly>
    <div style="margin-top:6px"><button class="small" id="sub-copy">复制</button></div>

    <label style="margin-top:14px">Clash / Clash Meta / Stash</label>
    <input id="sub-clash" readonly>
    <div style="margin-top:6px"><button class="small" id="sub-copy-clash">复制</button></div>

    <label style="margin-top:14px">Sing-box (sfm / sfa / sfi)</label>
    <input id="sub-singbox" readonly>
    <div style="margin-top:6px"><button class="small" id="sub-copy-singbox">复制</button></div>

    <label style="margin-top:14px">单节点 URI (手动导入)</label>
    <input id="sub-vless" readonly>
    <div style="margin-top:6px;display:flex;gap:6px;align-items:center">
      <button class="small ghost" id="vless-copy">复制 VLESS</button>
      <button class="small ghost" id="trojan-copy">复制 Trojan</button>
    </div>

    <div style="margin-top:14px;padding:10px 12px;background:#0f1a30;border:1px solid #1f2d4a;border-radius:8px;font-size:12px;color:#8ba3c7">
      协议切换：去「节点设置」tab 勾选 VLESS / Trojan，保存后通用订阅会自动包含所有启用的协议。
    </div>

    <div style="margin-top:16px;text-align:right">
      <button class="ghost" id="sub-close">关闭</button>
    </div>
  </div>
</div>

<div id="toast" class="toast"></div>

<script>
const $ = sel => document.querySelector(sel);
const WORKER_ORIGIN = location.origin;
let token = localStorage.getItem('admin_token') || '';

function toast(msg) {
  const t = $('#toast'); t.textContent = msg; t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 1800);
}

async function api(path, opt = {}) {
  const r = await fetch(WORKER_ORIGIN + path, {
    ...opt,
    headers: { 'Authorization': 'Bearer ' + token,
               'content-type': 'application/json', ...(opt.headers || {}) }
  });
  if (r.status === 401) { localStorage.removeItem('admin_token'); showLogin(); throw new Error('401'); }
  return r.json();
}

function fmtBytes(b) {
  if (!b) return '0';
  const u = ['B','KB','MB','GB','TB']; let i = 0;
  while (b >= 1024 && i < 4) { b /= 1024; i++; }
  return b.toFixed(b < 10 ? 1 : 0) + ' ' + u[i];
}
function fmtDate(s) {
  if (!s) return '∞';
  const d = new Date(s); const now = Date.now();
  const dd = Math.floor((d - now) / 86400000);
  if (dd < 0) return '已过期 ' + (-dd) + '天';
  if (dd < 30) return dd + '天后';
  return d.toISOString().slice(0,10);
}
function bar(used, total) {
  if (!total) return '<span class="muted">不限</span>';
  const pct = Math.min(100, used/total*100);
  const cls = pct > 95 ? 'err' : pct > 80 ? 'warn' : '';
  return fmtBytes(used) + ' / ' + fmtBytes(total) + '<div class="bar"><div class="bar-fill '+cls+'" style="width:'+pct+'%"></div></div>';
}

function showLogin() { $('#dashboard').style.display = 'none'; $('#login-screen').style.display = 'block'; }
function showDash() { $('#login-screen').style.display = 'none'; $('#dashboard').style.display = 'block'; refresh(); }

$('#login-btn').onclick = async () => {
  token = $('#token-input').value.trim();
  if (!token) return;
  try {
    await api('/admin/health');
    localStorage.setItem('admin_token', token);
    showDash();
  } catch (e) {
    $('#login-err').textContent = '登录失败：Token 不对 or ADMIN_TOKEN 没配 or D1/KV 没绑定';
  }
};
$('#token-input').onkeydown = e => { if (e.key === 'Enter') $('#login-btn').click(); };

$('#logout-btn').onclick = () => { localStorage.removeItem('admin_token'); token = ''; showLogin(); };
$('#refresh-btn').onclick = () => refresh();

async function refresh() {
  try {
    const [h, u] = await Promise.all([api('/admin/health'), api('/admin/users')]);
    $('#s-users').textContent = h.users_enabled ?? 0;
    $('#s-pending').textContent = h.traffic_buffer_pending ?? 0;
    $('#s-sync').textContent = h.panel_configured ? '面板模式' : '本地模式';
    renderUsers(u.users || []);
  } catch (e) {}
}

function renderUsers(list) {
  const tb = $('#users-tbody');
  if (!list.length) {
    tb.innerHTML = '<tr><td colspan="7" class="muted" style="text-align:center;padding:30px">暂无用户，点击右上「新建用户」</td></tr>';
    return;
  }
  tb.innerHTML = list.map(u => {
    const daily = bar(u.daily_used_bytes, u.daily_quota_bytes);
    const total = bar(u.total_used_bytes, u.total_quota_bytes);
    const expired = u.expire_at && new Date(u.expire_at) < new Date();
    let status = '<span class="badge ok">正常</span>';
    if (!u.enabled) status = '<span class="badge err">已禁用</span>';
    else if (expired) status = '<span class="badge err">已过期</span>';
    else if (u.daily_quota_bytes && u.daily_used_bytes >= u.daily_quota_bytes) status = '<span class="badge warn">日超限</span>';
    const toggleLabel = u.enabled ? '停用账号' : '启用账号';
    return \`<tr>
      <td>\${u.email || '—'}</td>
      <td class="muted" style="font-family:ui-monospace;font-size:11px">\${u.uuid.slice(0,8)}...\${u.uuid.slice(-4)}</td>
      <td>\${daily}</td>
      <td>\${total}</td>
      <td>\${fmtDate(u.expire_at)}</td>
      <td>\${status}</td>
      <td class="actions">
        <button class="small" data-act="sub" data-uuid="\${u.uuid}" data-email="\${u.email||''}">订阅</button>
        <span class="action-wrap">
          <button class="small ghost" data-act="menu" data-uuid="\${u.uuid}">操作 ▾</button>
          <div class="action-menu" data-menu="\${u.uuid}">
            <button data-act="toggle" data-uuid="\${u.uuid}">\${toggleLabel}</button>
            <button data-act="unblock" data-uuid="\${u.uuid}">解封（清日超限标记）</button>
            <hr>
            <button data-act="extend" data-days="30" data-uuid="\${u.uuid}">延期 30 天</button>
            <button data-act="extend" data-days="90" data-uuid="\${u.uuid}">延期 90 天</button>
            <button data-act="extend" data-days="365" data-uuid="\${u.uuid}">延期 365 天</button>
            <hr>
            <button data-act="reset-daily" data-uuid="\${u.uuid}">重置日流量</button>
            <button data-act="reset-total" data-uuid="\${u.uuid}">重置总流量</button>
            <hr>
            <button class="danger-item" data-act="del" data-uuid="\${u.uuid}">删除用户</button>
          </div>
        </span>
      </td>
    </tr>\`;
  }).join('');
}

// 关闭所有打开的操作菜单
function closeAllActionMenus() {
  document.querySelectorAll('.action-menu.show').forEach(m => m.classList.remove('show'));
}

document.addEventListener('click', async (e) => {
  const act = e.target.dataset?.act;
  // 点击外部关菜单
  if (!e.target.closest('.action-wrap')) closeAllActionMenus();
  if (!act) return;
  const uuid = e.target.dataset.uuid;

  if (act === 'menu') {
    // 打开/关闭当前行菜单
    const menu = document.querySelector(\`.action-menu[data-menu="\${uuid}"]\`);
    const wasOpen = menu?.classList.contains('show');
    closeAllActionMenus();
    if (menu && !wasOpen) menu.classList.add('show');
    return;
  }
  closeAllActionMenus();

  if (act === 'del') {
    if (!confirm('确定删除这个用户？流量记录一起清除。')) return;
    await api('/admin/user?uuid=' + uuid, { method: 'DELETE' });
    toast('已删除'); refresh();
  } else if (act === 'unblock') {
    await api('/admin/unblock?uuid=' + uuid, { method: 'POST' });
    await api('/admin/reset-daily?uuid=' + uuid, { method: 'POST' });
    toast('已解封并重置日流量'); refresh();
  } else if (act === 'reset-daily') {
    await api('/admin/reset-daily?uuid=' + uuid, { method: 'POST' });
    toast('日流量已清零'); refresh();
  } else if (act === 'reset-total') {
    if (!confirm('重置该用户总流量计数？额度不变。')) return;
    await api('/admin/user/reset-total?uuid=' + uuid, { method: 'POST' });
    toast('总流量已清零'); refresh();
  } else if (act === 'toggle') {
    const r = await api('/admin/user/toggle?uuid=' + uuid, { method: 'POST' });
    toast(r.enabled ? '已启用' : '已停用'); refresh();
  } else if (act === 'extend') {
    const days = e.target.dataset.days;
    await api('/admin/user/extend?uuid=' + uuid + '&days=' + days, { method: 'POST' });
    toast('已延期 ' + days + ' 天'); refresh();
  } else if (act === 'sub') {
    showSubModal(uuid, e.target.dataset.email);
  }
});

let currentSubUuid = '';
function showSubModal(uuid, email) {
  currentSubUuid = uuid;
  const host = location.host;
  const remark = encodeURIComponent((email || 'node') + '@' + host.split('.')[0]);
  const vless = \`vless://\${uuid}@\${host}:443?encryption=none&security=tls&type=ws&host=\${host}&path=%2F&sni=\${host}#\${remark}\`;
  const base = \`\${location.origin}/sub/\${uuid}\`;
  const page = \`\${location.origin}/p/\${uuid}\`;
  $('#sub-page').value = page;
  $('#sub-url').value = base;
  $('#sub-clash').value = base + '?sub=clash';
  $('#sub-singbox').value = base + '?sub=singbox';
  $('#sub-vless').value = vless;
  $('#sub-modal').classList.add('show');
}
const copyFrom = (sel, label) => () => { navigator.clipboard.writeText($(sel).value); toast('已复制 ' + label); };
$('#sub-copy-page').onclick    = copyFrom('#sub-page',    '客户订阅页');
$('#sub-open-page').onclick    = () => window.open($('#sub-page').value, '_blank');
$('#sub-copy').onclick         = copyFrom('#sub-url',     '通用订阅');
$('#sub-copy-clash').onclick   = copyFrom('#sub-clash',   'Clash 订阅');
$('#sub-copy-singbox').onclick = copyFrom('#sub-singbox', 'Sing-box 订阅');
$('#vless-copy').onclick       = copyFrom('#sub-vless',   'VLESS 链接');
$('#trojan-copy').onclick      = async () => {
  // 实时从 settings 读 TROJAN_PATH, 构造 trojan URI
  try {
    const r = await api('/admin/settings');
    const s = r.settings || {};
    const trojanPath = s.TROJAN_PATH || '/trojan';
    const host = location.host;
    const uri = \`trojan://\${currentSubUuid}@\${host}:443?security=tls&type=ws&host=\${host}&path=\${encodeURIComponent(trojanPath)}&sni=\${host}#\${encodeURIComponent(host.split('.')[0] + '-trojan')}\`;
    navigator.clipboard.writeText(uri);
    toast('已复制 Trojan 链接');
  } catch (e) { toast('读取配置失败'); }
};
$('#sub-close').onclick = () => $('#sub-modal').classList.remove('show');

// --- Tab 切换 ---
document.querySelectorAll('.tab-btn').forEach(b => {
  b.onclick = () => {
    document.querySelectorAll('.tab-btn').forEach(x => x.classList.remove('active'));
    b.classList.add('active');
    const tab = b.dataset.tab;
    $('#pane-users').style.display    = tab === 'users'    ? 'block' : 'none';
    $('#pane-settings').style.display = tab === 'settings' ? 'block' : 'none';
    if (tab === 'settings') loadSettings();
  };
});

// --- 节点设置加载/保存 ---
// SETTING_KEYS: 走 value 字段直接存的 key (ADDRESSES/ADDAPI 由表格 UI 序列化进来)
const SETTING_KEYS = ['PROXYIP', 'ADDRESSES', 'ADDAPI', 'ADDCSV', 'NODE_NAME_PREFIX', 'WS_PATH', 'TROJAN_PATH', 'SOCKS5'];

// 常用地区列表 (order 决定 chip 展示顺序)
const COMMON_REGIONS = [
  { k:'us', n:'美国' }, { k:'hk', n:'香港' }, { k:'jp', n:'日本' }, { k:'sg', n:'新加坡' },
  { k:'tw', n:'台湾' }, { k:'kr', n:'韩国' }, { k:'de', n:'德国' }, { k:'gb', n:'英国' },
  { k:'nl', n:'荷兰' }, { k:'fr', n:'法国' }, { k:'ca', n:'加拿大' }, { k:'au', n:'澳大利亚' },
  { k:'in', n:'印度' }, { k:'th', n:'泰国' }, { k:'my', n:'马来' }, { k:'vn', n:'越南' },
  { k:'br', n:'巴西' }, { k:'ae', n:'迪拜' }, { k:'il', n:'以色列' }, { k:'ru', n:'俄罗斯' },
  { k:'auto', n:'未分类' },
];

// 预置的公开优选源 (勾选即启用)
const DEFAULT_ADDAPI_PRESETS = [
  { url: 'https://ipdb.api.030101.xyz/?type=bestcf',    name: 'ipdb · bestcf (混合优选)',  region: 'auto', tag: 'cf-pool' },
  { url: 'https://ipdb.api.030101.xyz/?type=bestproxy', name: 'ipdb · bestproxy (反代候选)', region: 'auto', tag: 'proxy-pool' },
  { url: 'https://ipdb.api.030101.xyz/?type=cfv4',      name: 'ipdb · cfv4 (IPv4)',        region: 'auto', tag: 'cfv4' },
  { url: 'https://addressesapi.090227.xyz/cf',          name: '090227 · CF 优选',          region: 'us',   tag: '090227-cf' },
  { url: 'https://addressesapi.090227.xyz/ct',          name: '090227 · 电信优选',          region: 'us',   tag: '090227-ct' },
];

// --- 节点表格 UI ---
function serializeNodeRow(row) {
  const addr = row.querySelector('.nd-addr').value.trim();
  if (!addr) return null;
  const port   = row.querySelector('.nd-port').value.trim();
  const remark = row.querySelector('.nd-remark').value.trim();
  const region = row.querySelector('.nd-region').value;
  const tags   = row.querySelector('.nd-tags').value.trim();
  const pv = row.querySelector('.nd-pv').checked;
  const pt = row.querySelector('.nd-pt').checked;
  const parts = [addr + (port && port !== '443' ? ':' + port : '')];
  if (remark) parts.push('#' + remark);
  const attrs = [];
  if (region && region !== 'auto') attrs.push('region=' + region);
  if (tags) {
    const ts = tags.split(/[,\\s|]+/).filter(Boolean).join('|');
    if (ts) attrs.push('tag=' + ts);
  }
  if (pv !== pt) attrs.push('proto=' + (pv ? 'vless' : 'trojan'));
  let line = parts.join('');
  if (attrs.length) line += ' [' + attrs.join(',') + ']';
  return line;
}
function serializeAddresses() {
  const rows = document.querySelectorAll('#nodes-tbody tr');
  const lines = [];
  rows.forEach(r => { const l = serializeNodeRow(r); if (l) lines.push(l); });
  return lines.join('\\n');
}
function parseLineToFields(line) {
  // 复用后端逻辑的简版: 先剥 [attrs], 再切 #, 再 addr:port
  let work = line.trim();
  let attrBlock = '';
  const m = work.match(/^(.*?)\\s*\\[([^\\]]*)\\]\\s*$/);
  if (m) { work = m[1].trim(); attrBlock = m[2]; }
  const h = work.indexOf('#');
  const addrPart = h >= 0 ? work.slice(0, h).trim() : work;
  const remark   = h >= 0 ? work.slice(h + 1).trim() : '';
  const [addrS, portS] = addrPart.split(':');
  const out = { addr: (addrS || '').trim(), port: portS || '443', remark, region: 'auto', tags: '', pv: true, pt: true };
  if (attrBlock) {
    for (const kv of attrBlock.split(',')) {
      const [k, v] = kv.split('=').map(x => x && x.trim());
      if (!k || v === undefined) continue;
      if (k === 'region') out.region = v.toLowerCase();
      else if (k === 'tag') out.tags = v.replace(/\\|/g, ', ');
      else if (k === 'proto') {
        const list = v.split('|').map(x => x.trim().toLowerCase());
        out.pv = list.includes('vless');
        out.pt = list.includes('trojan');
      }
    }
  }
  return out;
}
function makeRegionOpts(selected) {
  return COMMON_REGIONS.map(r =>
    \`<option value="\${r.k}" \${r.k === selected ? 'selected' : ''}>\${r.k === 'auto' ? '未分类' : r.k.toUpperCase() + ' · ' + r.n}</option>\`
  ).join('');
}
function addNodeRow(data) {
  const d = data || { addr: '', port: '443', remark: '', region: 'auto', tags: '', pv: true, pt: true };
  const tr = document.createElement('tr');
  tr.className = 'node-row';
  tr.innerHTML = \`
    <td><input class="nd-addr"   placeholder="addr 或 domain" value="\${d.addr.replace(/"/g,'&quot;')}"></td>
    <td><input class="nd-port"   placeholder="443" value="\${d.port}"></td>
    <td><input class="nd-remark" placeholder="备注" value="\${(d.remark||'').replace(/"/g,'&quot;')}"></td>
    <td><select class="nd-region">\${makeRegionOpts(d.region || 'auto')}</select></td>
    <td><input class="nd-tags"   placeholder="premium, fast" value="\${(d.tags||'').replace(/"/g,'&quot;')}"></td>
    <td><div class="proto-cell">
      <label><input type="checkbox" class="nd-pv" \${d.pv !== false ? 'checked' : ''}>V</label>
      <label><input type="checkbox" class="nd-pt" \${d.pt !== false ? 'checked' : ''}>T</label>
    </div></td>
    <td><button type="button" class="del-btn" data-act="nd-del">×</button></td>\`;
  $('#nodes-tbody').appendChild(tr);
}
function loadAddressesIntoTable(text) {
  $('#nodes-tbody').innerHTML = '';
  const lines = (text || '').split(/\\r?\\n/).map(l => l.trim()).filter(l => l && !l.startsWith('#'));
  if (lines.length === 0) { addNodeRow(); return; }
  lines.forEach(l => addNodeRow(parseLineToFields(l)));
}

// --- 优选源清单 ---
function serializeAddapi() {
  const rows = document.querySelectorAll('#addapi-ui .src-item');
  const lines = [];
  rows.forEach(row => {
    const enabled = row.querySelector('.sw-input').checked;
    if (!enabled) return;
    const url = row.querySelector('.s-url').value.trim();
    if (!url) return;
    const region = row.querySelector('.s-region').value;
    const tag    = row.querySelector('.s-tag').value.trim();
    const attrs = [];
    if (region && region !== 'auto') attrs.push('region=' + region);
    if (tag) attrs.push('tag=' + tag);
    lines.push(attrs.length ? \`\${url} [\${attrs.join(',')}]\` : url);
  });
  return lines.join('\\n');
}
function parseAddapiLine(line) {
  let work = line.trim();
  let attrBlock = '';
  const m = work.match(/^(.*?)\\s*\\[([^\\]]*)\\]\\s*$/);
  if (m) { work = m[1].trim(); attrBlock = m[2]; }
  const out = { url: work, region: 'auto', tag: '' };
  if (attrBlock) {
    for (const kv of attrBlock.split(',')) {
      const [k, v] = kv.split('=').map(x => x && x.trim());
      if (k === 'region') out.region = v;
      if (k === 'tag')    out.tag    = v;
    }
  }
  return out;
}
function addAddapiRow(data, isPreset) {
  const d = data || { url: '', region: 'auto', tag: '', name: '自定义源', enabled: true };
  const name = d.name || (isPreset ? '预设' : '自定义源');
  const row = document.createElement('div');
  row.className = 'src-item' + (d.enabled === false ? ' off' : '');
  row.innerHTML = \`
    <div class="sw"><input type="checkbox" class="sw-input" \${d.enabled !== false ? 'checked' : ''}></div>
    <div class="name-row"><span class="n">\${name.replace(/</g,'&lt;')}</span><span class="u">\${d.url.replace(/</g,'&lt;') || '(点右侧粘贴 URL)'}</span></div>
    <select class="s-region">\${makeRegionOpts(d.region || 'auto')}</select>
    <input class="s-tag" placeholder="标签(tag)" value="\${(d.tag||'').replace(/"/g,'&quot;')}">
    <button type="button" class="del-btn" data-act="src-del">×</button>\`;
  // URL 可编辑: 双击 name row 弹出 prompt
  row.querySelector('.name-row').ondblclick = () => {
    const url = prompt('编辑 URL:', d.url);
    if (url !== null) {
      d.url = url.trim();
      row.querySelector('.u').textContent = d.url || '(点右侧粘贴 URL)';
    }
  };
  row.querySelector('.sw-input').onchange = (e) => {
    row.classList.toggle('off', !e.target.checked);
  };
  $('#addapi-ui').appendChild(row);
}
function loadAddapiIntoUI(text) {
  const box = $('#addapi-ui');
  box.innerHTML = '';
  const raw = (text || '').split(/\\r?\\n/).map(l => l.trim()).filter(l => l && !l.startsWith('#'));
  const parsed = raw.map(parseAddapiLine);
  // 对每个预设: 如果当前配置里有，用当前配置的 region/tag; 否则按预设默认并 enabled=false
  for (const p of DEFAULT_ADDAPI_PRESETS) {
    const existing = parsed.find(x => x.url === p.url);
    addAddapiRow({
      url: p.url, name: p.name,
      region: existing ? existing.region : p.region,
      tag:    existing ? existing.tag    : p.tag,
      enabled: !!existing,
    }, true);
  }
  // 其余自定义 URL
  for (const x of parsed) {
    if (DEFAULT_ADDAPI_PRESETS.find(p => p.url === x.url)) continue;
    addAddapiRow({ url: x.url, name: '自定义源', region: x.region, tag: x.tag, enabled: true }, false);
  }
}

// --- 订阅筛选 chip ---
let _nodeFacets = { regions: [], tags: [] };  // 动态聚合
function renderRegionChips(containerSel, selectedSet, negative) {
  const box = $(containerSel);
  box.innerHTML = '';
  for (const r of COMMON_REGIONS) {
    if (r.k === 'auto') continue;
    const sel = selectedSet.has(r.k);
    const chip = document.createElement('span');
    chip.className = 'chip' + (sel ? ' active' : '') + (negative ? ' neg' : '');
    chip.dataset.v = r.k;
    chip.innerHTML = \`\${r.k.toUpperCase()} <span class="cnt">\${r.n}</span>\`;
    chip.onclick = () => {
      if (selectedSet.has(r.k)) selectedSet.delete(r.k); else selectedSet.add(r.k);
      chip.classList.toggle('active');
    };
    box.appendChild(chip);
  }
}
function renderTagChips(containerSel, selectedSet, negative) {
  const box = $(containerSel);
  box.innerHTML = '';
  const tags = _nodeFacets.tags || [];
  if (!tags.length) {
    box.innerHTML = '<span class="hint" style="margin:0">（当前节点池还没有任何标签。先在节点列表或优选源里打 tag，这里会自动列出）</span>';
    return;
  }
  for (const t of tags) {
    const sel = selectedSet.has(t.k);
    const chip = document.createElement('span');
    chip.className = 'chip' + (sel ? ' active' : '') + (negative ? ' neg' : '');
    chip.dataset.v = t.k;
    chip.innerHTML = \`\${t.k} <span class="cnt">×\${t.n}</span>\`;
    chip.onclick = () => {
      if (selectedSet.has(t.k)) selectedSet.delete(t.k); else selectedSet.add(t.k);
      chip.classList.toggle('active');
    };
    box.appendChild(chip);
  }
}
function renderBtnGroup(containerSel, value) {
  const box = $(containerSel);
  box.querySelectorAll('button').forEach(b => {
    b.classList.toggle('active', Number(b.dataset.v) === Number(value));
    b.onclick = () => {
      box.querySelectorAll('button').forEach(x => x.classList.remove('active'));
      b.classList.add('active');
    };
  });
}
function getBtnGroupValue(containerSel) {
  const active = $(containerSel + ' button.active');
  return active ? Number(active.dataset.v) : 0;
}

// 当前的筛选选中集合 (Set)
const _filterState = {
  regions: new Set(),
  exclude_regions: new Set(),
  include_tags: new Set(),
  exclude_tags: new Set(),
  max_per_region: 0,
  total_max: 60,
};

function parseFilterFromUI() {
  return {
    regions:         [..._filterState.regions],
    exclude_regions: [..._filterState.exclude_regions],
    include_tags:    [..._filterState.include_tags],
    exclude_tags:    [..._filterState.exclude_tags],
    max_per_region:  getBtnGroupValue('#f-max-per-region-btns'),
    total_max:       getBtnGroupValue('#f-total-max-btns'),
  };
}
function writeFilterToUI(f) {
  _filterState.regions         = new Set(f.regions || []);
  _filterState.exclude_regions = new Set(f.exclude_regions || []);
  _filterState.include_tags    = new Set(f.include_tags || []);
  _filterState.exclude_tags    = new Set(f.exclude_tags || []);
  renderRegionChips('#f-regions-chips',          _filterState.regions, false);
  renderRegionChips('#f-exclude-regions-chips',  _filterState.exclude_regions, true);
  renderTagChips   ('#f-include-tags-chips',     _filterState.include_tags, false);
  renderTagChips   ('#f-exclude-tags-chips',     _filterState.exclude_tags, true);
  renderBtnGroup('#f-max-per-region-btns', f.max_per_region || 0);
  renderBtnGroup('#f-total-max-btns',      f.total_max || 60);
}

async function refreshFacetsThenRewireTagChips() {
  try {
    const r = await api('/admin/node-facets');
    if (r.ok) {
      _nodeFacets = { regions: r.regions || [], tags: r.tags || [] };
      renderTagChips('#f-include-tags-chips', _filterState.include_tags, false);
      renderTagChips('#f-exclude-tags-chips', _filterState.exclude_tags, true);
    }
  } catch {}
}

async function loadSettings() {
  try {
    const r = await api('/admin/settings');
    const s = r.settings || {};
    for (const k of SETTING_KEYS) {
      const el = $('#st-' + k);
      if (el) el.value = s[k] || '';
    }
    // 节点表格从 ADDRESSES 填
    loadAddressesIntoTable(s.ADDRESSES || '');
    // 优选源清单从 ADDAPI 填
    loadAddapiIntoUI(s.ADDAPI || '');
    // ENABLED_PROTOCOLS 复选框
    const protos = (s.ENABLED_PROTOCOLS || 'vless').split(/[,\\s]+/).map(x => x.trim().toLowerCase());
    $('#st-proto-vless').checked  = protos.includes('vless');
    $('#st-proto-trojan').checked = protos.includes('trojan');
    // NODE_FILTER
    let filter = { regions: [], exclude_regions: [], include_tags: [], exclude_tags: [], max_per_region: 0, total_max: 60 };
    try {
      if (s.NODE_FILTER) filter = Object.assign(filter, JSON.parse(s.NODE_FILTER));
    } catch {}
    writeFilterToUI(filter);
    if (r.warn) toast('⚠ ' + r.warn);
    // 读完后异步拉取 facets 渲染标签 chip
    refreshFacetsThenRewireTagChips();
  } catch (e) { toast('读取失败: ' + e.message); }
}

$('#st-reload').onclick = loadSettings;
$('#st-f-reload').onclick = loadSettings;

$('#st-save').onclick = async () => {
  const body = {};
  for (const k of SETTING_KEYS) {
    if (k === 'ADDRESSES' || k === 'ADDAPI') continue;   // 这两个由表格/清单序列化
    const el = $('#st-' + k);
    if (el && !el.disabled) body[k] = el.value;
  }
  body.ADDRESSES = serializeAddresses();
  body.ADDAPI    = serializeAddapi();
  const protos = [];
  if ($('#st-proto-vless').checked)  protos.push('vless');
  if ($('#st-proto-trojan').checked) protos.push('trojan');
  body.ENABLED_PROTOCOLS = protos.length ? protos.join(',') : 'vless';
  try {
    await api('/admin/settings', { method: 'POST', body: JSON.stringify(body) });
    toast('✓ 已保存，60 秒内生效');
    refreshFacetsThenRewireTagChips();
  } catch (e) { toast('保存失败: ' + e.message); }
};

$('#st-f-save').onclick = async () => {
  const body = { NODE_FILTER: JSON.stringify(parseFilterFromUI()) };
  try {
    await api('/admin/settings', { method: 'POST', body: JSON.stringify(body) });
    toast('✓ 筛选规则已保存，60 秒内生效');
  } catch (e) { toast('保存失败: ' + e.message); }
};

// 节点表格按钮
$('#nodes-add').onclick = () => addNodeRow();
$('#nodes-add-preset').onclick = () => {
  // 常用反代/优选节点一键加三行
  addNodeRow({ addr: 'visa.com',      port: '443', remark: 'US CF优选', region: 'us', tags: 'cf,premium', pv: true, pt: true });
  addNodeRow({ addr: 'cf.090227.xyz', port: '443', remark: '反代',      region: 'us', tags: 'proxy',      pv: true, pt: true });
  addNodeRow({ addr: 'www.visa.com.hk', port: '443', remark: '港区',   region: 'hk', tags: 'cf',        pv: true, pt: true });
};
$('#nodes-toggle-text').onclick = (e) => {
  e.preventDefault();
  $('#st-ADDRESSES').value = serializeAddresses();
  $('#nodes-ui').style.display = 'none';
  $('#nodes-text').style.display = 'block';
};
$('#nodes-toggle-ui').onclick = (e) => {
  e.preventDefault();
  loadAddressesIntoTable($('#st-ADDRESSES').value);
  $('#nodes-text').style.display = 'none';
  $('#nodes-ui').style.display = 'block';
};
$('#nodes-tbody').addEventListener('click', (e) => {
  if (e.target.dataset.act === 'nd-del') {
    e.target.closest('tr')?.remove();
  }
});

// 优选源按钮
$('#addapi-add').onclick = () => {
  const url = prompt('输入优选源 URL (例如 https://xxx.com/list.txt):');
  if (url) addAddapiRow({ url: url.trim(), name: '自定义源', region: 'auto', tag: '', enabled: true }, false);
};
$('#addapi-toggle-text').onclick = (e) => {
  e.preventDefault();
  $('#st-ADDAPI').value = serializeAddapi();
  $('#addapi-ui').style.display = 'none';
  $('#addapi-toggle-text').parentElement.style.display = 'none';
  $('#addapi-text').style.display = 'block';
  $('#addapi-add').style.display = 'none';
};
$('#addapi-toggle-ui').onclick = (e) => {
  e.preventDefault();
  loadAddapiIntoUI($('#st-ADDAPI').value);
  $('#addapi-text').style.display = 'none';
  $('#addapi-toggle-text').parentElement.style.display = '';
  $('#addapi-ui').style.display = '';
  $('#addapi-add').style.display = '';
};
$('#addapi-ui').addEventListener('click', (e) => {
  if (e.target.dataset.act === 'src-del') {
    e.target.closest('.src-item')?.remove();
  }
});
$('#st-f-preview').onclick = async () => {
  // 先保存当前 UI 规则, 再预览 (保证用户改了没点保存也能看到效果)
  try {
    await api('/admin/settings', {
      method: 'POST',
      body: JSON.stringify({ NODE_FILTER: JSON.stringify(parseFilterFromUI()) })
    });
    const r = await api('/admin/preview-nodes');
    const box = $('#st-f-preview-result');
    const tbody = $('#st-f-preview-tbody');
    tbody.innerHTML = '';
    for (const n of (r.nodes || [])) {
      const tr = document.createElement('tr');
      tr.innerHTML = \`
        <td style="padding:5px 8px;border-top:1px solid #1f2d4a">\${n.addr}:\${n.port}</td>
        <td style="padding:5px 8px;border-top:1px solid #1f2d4a;color:#7fb3ff">\${n.region || 'auto'}</td>
        <td style="padding:5px 8px;border-top:1px solid #1f2d4a;color:#8ba3c7">\${(n.tags||[]).join(', ') || '—'}</td>
        <td style="padding:5px 8px;border-top:1px solid #1f2d4a;color:#a8bfe0">\${n.protos ? n.protos.join('+') : '默认'}</td>
        <td style="padding:5px 8px;border-top:1px solid #1f2d4a;color:#6b7f9f">\${n.source}</td>
      \`;
      tbody.appendChild(tr);
    }
    const byRegion = r.by_region || {};
    const regionSum = Object.entries(byRegion)
      .sort((a,b) => b[1] - a[1])
      .map(([k,v]) => \`<span style="display:inline-block;padding:2px 8px;margin:2px;background:#1b2942;border-radius:4px;color:#a8bfe0"><b>\${k}</b>:\${v}</span>\`)
      .join('');
    $('#st-f-preview-summary').innerHTML =
      \`合成池 <b style="color:#fff">\${r.total_before}</b> 个 → 筛后 <b style="color:#7fb3ff">\${r.total_after}</b> 个<br>\${regionSum || ''}\`;
    box.style.display = 'block';
  } catch (e) { toast('预览失败: ' + e.message); }
};

$('#new-user-btn').onclick = () => {
  // 重置: 默认选中月卡
  document.querySelectorAll('#plan-cards .plan-card').forEach(c => c.classList.remove('active'));
  $('#plan-cards .plan-card[data-plan="monthly"]').classList.add('active');
  $('#custom-fields').style.display = 'none';
  $('#f-email').value = '';
  $('#new-modal').classList.add('show');
};
$('#new-cancel').onclick = () => $('#new-modal').classList.remove('show');

// 套餐卡片点选
document.querySelectorAll('#plan-cards .plan-card').forEach(card => {
  card.onclick = () => {
    document.querySelectorAll('#plan-cards .plan-card').forEach(c => c.classList.remove('active'));
    card.classList.add('active');
    // 自定义 → 展开输入区
    $('#custom-fields').style.display = card.dataset.plan === 'custom' ? 'block' : 'none';
  };
});

$('#new-submit').onclick = async () => {
  const active = $('#plan-cards .plan-card.active');
  if (!active) { toast('请选择一个套餐'); return; }
  let total, daily, days;
  if (active.dataset.plan === 'custom') {
    total = parseFloat($('#f-total').value) || 0;
    daily = parseFloat($('#f-daily').value) || 0;
    days  = parseInt($('#f-days').value) || 0;
  } else {
    total = parseFloat(active.dataset.total) || 0;
    daily = parseFloat(active.dataset.daily) || 0;
    days  = parseInt(active.dataset.days) || 0;
  }
  const body = {
    email: $('#f-email').value || null,
    daily_quota_gb: daily,
    total_quota_gb: total,
    expire_days: days,
  };
  const r = await api('/admin/user', { method: 'POST', body: JSON.stringify(body) });
  $('#new-modal').classList.remove('show');
  toast('已创建用户');
  refresh();
  showSubModal(r.uuid, body.email);
};

if (token) { api('/admin/health').then(() => showDash()).catch(() => showLogin()); }
else showLogin();
</script>
</body></html>`;
