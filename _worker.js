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

// ---------- 从 ADDAPI / ADDCSV 拉优选 IP, KV 缓存 10 分钟 ----------
async function fetchOptimizedAddresses(env, settings) {
  const cached = await env.KV.get('optimized_ips');
  if (cached !== null) {
    try { return JSON.parse(cached); } catch {}
  }
  const list = [];

  // ADDAPI: 多个 URL 用换行或逗号分隔, 每 URL 返回 text, 每行 addr[:port][#备注]
  const addapiUrls = (settings.ADDAPI || '').split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
  for (const u of addapiUrls) {
    try {
      const r = await fetch(u, { cf: { cacheTtl: 300 } });
      if (!r.ok) continue;
      const txt = await r.text();
      for (const line of txt.split(/\r?\n/)) {
        const t = line.trim();
        if (!t || t.startsWith('#')) continue;
        const [addrPart, nameRaw] = t.split('#');
        const [addr, portStr] = addrPart.split(':');
        if (!addr) continue;
        list.push({
          addr: addr.trim(),
          port: Number(portStr) || 443,
          name: (nameRaw?.trim()) || addr.trim(),
        });
      }
    } catch {}
  }

  // ADDCSV: iptest 格式 ip,port,tls,速度,丢包... 第一行 header 跳过
  const addcsvUrls = (settings.ADDCSV || '').split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
  for (const u of addcsvUrls) {
    try {
      const r = await fetch(u, { cf: { cacheTtl: 300 } });
      if (!r.ok) continue;
      const txt = await r.text();
      const rows = txt.split(/\r?\n/).slice(1);
      for (const line of rows) {
        if (!line.trim()) continue;
        const cols = line.split(',').map(s => s.trim());
        const [ip, portStr, tls] = cols;
        if (!ip) continue;
        // 只取 TLS=TRUE 或 tls=1
        if (tls && !/^(true|1|yes)$/i.test(tls)) continue;
        list.push({ addr: ip, port: Number(portStr) || 443, name: ip });
      }
    } catch {}
  }

  // 限制总数(订阅太长客户端处理慢), 去重
  const seen = new Set();
  const uniq = [];
  for (const n of list) {
    const k = n.addr + ':' + n.port;
    if (seen.has(k)) continue;
    seen.add(k);
    uniq.push(n);
    if (uniq.length >= 60) break;
  }

  await env.KV.put('optimized_ips', JSON.stringify(uniq), { expirationTtl: 600 });
  return uniq;
}

function pumpRemoteToWS(remoteSocket, ws, vlessResponseHeader, connState, retry) {
  let headerSent = false;
  let hasIncoming = false;

  remoteSocket.readable
    .pipeTo(new WritableStream({
      async write(chunk) {
        hasIncoming = true;
        if (ws.readyState !== 1) throw new Error('ws closed');
        if (!headerSent) {
          const merged = new Uint8Array(vlessResponseHeader.byteLength + chunk.byteLength);
          merged.set(vlessResponseHeader, 0);
          merged.set(new Uint8Array(chunk), vlessResponseHeader.byteLength);
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

  // 解析本地地址列表, 一行一个, 格式 addr[:port][#备注]
  const addrLines = (settings.ADDRESSES || '').split(/\r?\n/).map(s => s.trim()).filter(l => l && !l.startsWith('#'));
  const nodes = [];
  addrLines.forEach((line, i) => {
    const [addrPart, nameRaw] = line.split('#');
    const [addr, portStr] = addrPart.split(':');
    if (!addr.trim()) return;
    nodes.push({
      addr: addr.trim(),
      port: Number(portStr) || 443,
      name: (nameRaw?.trim()) || `${prefix}-${i + 1}`,
    });
  });

  // 拼上 ADDAPI/ADDCSV 远程拉到的优选 IP
  try {
    const optimized = await fetchOptimizedAddresses(env, settings);
    optimized.forEach((n, i) => {
      nodes.push({ addr: n.addr, port: n.port, name: `${prefix}-优选-${i + 1}-${n.name}`.slice(0, 48) });
    });
  } catch {}

  // 兜底: 一个节点都没有, 就用当前 host
  if (nodes.length === 0) nodes.push({ addr: host, port: 443, name: prefix });

  // --- 格式解析: 显式 ?sub= > User-Agent 自动识别 > 默认 vless base64 ---
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

  // 构造 vless URI 列表
  const vlessUris = nodes.map(n =>
    `vless://${uuid}@${n.addr}:${n.port}?encryption=none&security=tls&type=ws&host=${wsHost}&path=${encodeURIComponent(wsPath)}&sni=${sni}#${encodeURIComponent(n.name)}`
  );

  const subInfoHeaders = {
    'content-type': 'text/plain; charset=utf-8',
    'subscription-userinfo': buildSubUserInfo(row),
    'profile-update-interval': '24',
  };

  // --- 格式分发 ---
  if (format === 'plain') {
    return new Response(vlessUris.join('\n'), { headers: subInfoHeaders });
  }

  if (format === 'clash') {
    const yaml = buildClashYaml(nodes, uuid, wsHost, wsPath, sni, prefix);
    return new Response(yaml, { headers: { ...subInfoHeaders, 'content-type': 'text/yaml; charset=utf-8' } });
  }

  if (format === 'singbox' || format === 'sing-box') {
    const json = buildSingBoxConfig(nodes, uuid, wsHost, wsPath, sni);
    return new Response(json, { headers: { ...subInfoHeaders, 'content-type': 'application/json; charset=utf-8' } });
  }

  // 默认 vless base64 (v2rayN / Shadowrocket / v2rayNG 都吃)
  const b64 = btoa(unescape(encodeURIComponent(vlessUris.join('\n') + '\n')));
  return new Response(b64, { headers: subInfoHeaders });
}

function buildClashYaml(nodes, uuid, wsHost, wsPath, sni, groupName) {
  const proxies = nodes.map(n => ({
    name: n.name,
    type: 'vless',
    server: n.addr,
    port: n.port,
    uuid,
    tls: true,
    'skip-cert-verify': false,
    servername: sni,
    network: 'ws',
    'ws-opts': { path: wsPath, headers: { Host: wsHost } },
    udp: true,
  }));
  const names = proxies.map(p => p.name);
  // 简易 YAML 序列化, 避免引 yaml 库
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
    y.push(`    type: vless`);
    y.push(`    server: ${p.server}`);
    y.push(`    port: ${p.port}`);
    y.push(`    uuid: ${p.uuid}`);
    y.push(`    tls: true`);
    y.push(`    servername: ${p.servername}`);
    y.push(`    network: ws`);
    y.push(`    ws-opts:`);
    y.push(`      path: "${p['ws-opts'].path}"`);
    y.push(`      headers:`);
    y.push(`        Host: ${p['ws-opts'].headers.Host}`);
    y.push(`    udp: true`);
  }
  y.push('proxy-groups:');
  y.push(`  - name: "${groupName || 'PROXY'}"`);
  y.push(`    type: select`);
  y.push(`    proxies:`);
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

function buildSingBoxConfig(nodes, uuid, wsHost, wsPath, sni) {
  const outbounds = nodes.map(n => ({
    type: 'vless',
    tag: n.name,
    server: n.addr,
    server_port: n.port,
    uuid,
    flow: '',
    tls: { enabled: true, server_name: sni, insecure: false },
    transport: { type: 'ws', path: wsPath, headers: { Host: wsHost } },
  }));
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
          <label>反代 IP (PROXYIP)</label>
          <div>
            <input id="st-PROXYIP" placeholder="空 = 不用反代, 例: cf.090227.xyz 或 1.2.3.4:443">
            <div class="hint">当 Cloudflare 被目标服务拉黑（如 TG/部分小众站）时，流量会自动兜底到这个 IP。可填 cmliu 的优选 <code>cf.090227.xyz</code> / <code>ProxyIP.US.CMLiussss.net</code>。</div>
          </div>

          <label>节点地址列表</label>
          <div>
            <textarea id="st-ADDRESSES" placeholder="# 一行一个, 格式: addr[:port]#备注&#10;&#10;visa.com#美国-CF优选&#10;cf.090227.xyz:443#反代&#10;www.google.com#美国-谷歌&#10;104.16.0.1#港区"></textarea>
            <div class="hint">订阅里每行生成一个节点。空 = 只用当前 Pages 域名做单节点。支持任意指向 Cloudflare 边缘的域名/IP（CNAME、优选IP、反代 IP 都行），端口一般 443。</div>
          </div>

          <label>优选IP API (ADDAPI)</label>
          <div>
            <textarea id="st-ADDAPI" placeholder="# 一行一个 URL, 返回 text, 每行 addr[:port][#备注]&#10;&#10;https://ipdb.api.030101.xyz/?type=bestcf&#10;https://ipdb.api.030101.xyz/?type=bestproxy"></textarea>
            <div class="hint">远端 TXT 形式的优选 IP 源。订阅时按需拉取（KV 缓存 10 分钟），自动合并进节点列表。常用公开源：<code>ipdb.api.030101.xyz/?type=bestcf</code>。多个 URL 用换行或逗号分隔。</div>
          </div>

          <label>优选IP CSV (ADDCSV)</label>
          <div>
            <input id="st-ADDCSV" placeholder="https://example.com/result.csv">
            <div class="hint">iptest 格式 CSV（表头 <code>ip,port,tls,...</code>），只取 <code>tls=TRUE</code> 的行。用于自建的 Cloudflare IP 测速结果。</div>
          </div>

          <label>节点名前缀</label>
          <div>
            <input id="st-NODE_NAME_PREFIX" placeholder="xiaox">
            <div class="hint">如果某行没写 <code>#备注</code>，就用这个前缀自动命名（xiaox-1、xiaox-2...）。</div>
          </div>

          <label>WebSocket 路径</label>
          <div>
            <input id="st-WS_PATH" placeholder="/">
            <div class="hint">客户端 ws path。默认 <code>/</code>。想增加隐蔽度可改 <code>/api</code> <code>/xxx</code>。改了要所有订阅重新拉一次。</div>
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
    </div>

  </div>
</div>

<div id="new-modal" class="modal">
  <div class="modal-inner">
    <h1 style="font-size:18px;margin-bottom:16px">新建用户</h1>
    <div class="preset">
      <button data-p="monthly">月卡 100GB/30天</button>
      <button data-p="quarterly">季卡 300GB/90天</button>
      <button data-p="yearly">年卡 1TB/365天</button>
    </div>
    <label>邮箱/标签</label>
    <input id="f-email" placeholder="user@example.com">
    <div class="row" style="margin-top:10px">
      <div><label>每日限额 (GB)</label><input id="f-daily" type="number" value="0" step="0.1"></div>
      <div><label>总流量 (GB)</label><input id="f-total" type="number" value="100" step="0.1"></div>
      <div><label>有效期 (天)</label><input id="f-days" type="number" value="30"></div>
    </div>
    <div style="margin-top:16px;display:flex;gap:8px;justify-content:flex-end">
      <button class="ghost" id="new-cancel">取消</button>
      <button id="new-submit">创建</button>
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

    <label style="margin-top:14px">VLESS 单节点 (手动导入)</label>
    <input id="sub-vless" readonly>
    <div style="margin-top:6px"><button class="small ghost" id="vless-copy">复制</button></div>

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
    return \`<tr>
      <td>\${u.email || '—'}</td>
      <td class="muted" style="font-family:ui-monospace;font-size:11px">\${u.uuid.slice(0,8)}...\${u.uuid.slice(-4)}</td>
      <td>\${daily}</td>
      <td>\${total}</td>
      <td>\${fmtDate(u.expire_at)}</td>
      <td>\${status}</td>
      <td class="actions">
        <button class="small" data-act="sub" data-uuid="\${u.uuid}" data-email="\${u.email||''}">订阅</button>
        <button class="small ghost" data-act="unblock" data-uuid="\${u.uuid}">解封</button>
        <button class="small danger" data-act="del" data-uuid="\${u.uuid}">删除</button>
      </td>
    </tr>\`;
  }).join('');
}

document.addEventListener('click', async (e) => {
  const act = e.target.dataset?.act;
  if (!act) return;
  const uuid = e.target.dataset.uuid;
  if (act === 'del') {
    if (!confirm('确定删除这个用户？')) return;
    await api('/admin/user?uuid=' + uuid, { method: 'DELETE' });
    toast('已删除'); refresh();
  } else if (act === 'unblock') {
    await api('/admin/unblock?uuid=' + uuid, { method: 'POST' });
    await api('/admin/reset-daily?uuid=' + uuid, { method: 'POST' });
    toast('已解封并重置日流量'); refresh();
  } else if (act === 'sub') {
    showSubModal(uuid, e.target.dataset.email);
  }
});

function showSubModal(uuid, email) {
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
const SETTING_KEYS = ['PROXYIP', 'ADDRESSES', 'ADDAPI', 'ADDCSV', 'NODE_NAME_PREFIX', 'WS_PATH', 'SOCKS5'];
async function loadSettings() {
  try {
    const r = await api('/admin/settings');
    const s = r.settings || {};
    for (const k of SETTING_KEYS) {
      const el = $('#st-' + k);
      if (el) el.value = s[k] || '';
    }
    if (r.warn) toast('⚠ ' + r.warn);
  } catch (e) { toast('读取失败: ' + e.message); }
}
$('#st-reload').onclick = loadSettings;
$('#st-save').onclick = async () => {
  const body = {};
  for (const k of SETTING_KEYS) {
    const el = $('#st-' + k);
    if (el && !el.disabled) body[k] = el.value;
  }
  try {
    await api('/admin/settings', { method: 'POST', body: JSON.stringify(body) });
    toast('✓ 已保存，60 秒内生效');
  } catch (e) { toast('保存失败: ' + e.message); }
};

$('#new-user-btn').onclick = () => $('#new-modal').classList.add('show');
$('#new-cancel').onclick = () => $('#new-modal').classList.remove('show');

document.querySelectorAll('.preset button').forEach(b => b.onclick = () => {
  const p = b.dataset.p;
  if (p === 'monthly')   { $('#f-daily').value = 0; $('#f-total').value = 100; $('#f-days').value = 30; }
  if (p === 'quarterly') { $('#f-daily').value = 0; $('#f-total').value = 300; $('#f-days').value = 90; }
  if (p === 'yearly')    { $('#f-daily').value = 0; $('#f-total').value = 1024; $('#f-days').value = 365; }
});

$('#new-submit').onclick = async () => {
  const body = {
    email: $('#f-email').value || null,
    daily_quota_gb: parseFloat($('#f-daily').value) || 0,
    total_quota_gb: parseFloat($('#f-total').value) || 0,
    expire_days: parseInt($('#f-days').value) || 0
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
