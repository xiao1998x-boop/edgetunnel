-- edgetunnel × Xboard MVP · D1 Schema
-- 执行: wrangler d1 execute edgetunnel-mvp --file=./schema.sql

-- ============================================================
-- 用户表：从 Xboard 同步，保留本地流量累计
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
  uuid              TEXT PRIMARY KEY,
  panel_user_id     INTEGER NOT NULL,
  email             TEXT,
  enabled           INTEGER NOT NULL DEFAULT 1,
  total_quota_bytes INTEGER NOT NULL DEFAULT 0,     -- 0 = 不限
  total_used_bytes  INTEGER NOT NULL DEFAULT 0,
  daily_quota_bytes INTEGER NOT NULL DEFAULT 0,     -- 0 = 不限（MVP 必接字段）
  daily_used_bytes  INTEGER NOT NULL DEFAULT 0,
  daily_reset_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  expire_at         TEXT,                            -- NULL = 永久
  conn_limit        INTEGER NOT NULL DEFAULT 0,      -- 并发设备数，0 = 不限
  speed_limit_kbps  INTEGER NOT NULL DEFAULT 0,      -- 预留，MVP 不用
  updated_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_users_panel_id ON users(panel_user_id);
CREATE INDEX IF NOT EXISTS idx_users_enabled ON users(enabled);

-- ============================================================
-- 流量缓冲表：连接结束写入，Cron 批量推给面板后清零
-- ============================================================
CREATE TABLE IF NOT EXISTS traffic_buffer (
  uuid       TEXT PRIMARY KEY,
  up_bytes   INTEGER NOT NULL DEFAULT 0,
  down_bytes INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- ============================================================
-- 节点状态表：记录 Cron 的运行时间、错误、最近同步用户数等
-- ============================================================
CREATE TABLE IF NOT EXISTS node_state (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- 初始化状态行
INSERT OR IGNORE INTO node_state (key, value) VALUES
  ('last_pull_users_at', ''),
  ('last_push_traffic_at', ''),
  ('last_daily_reset_at', ''),
  ('last_sync_user_count', '0'),
  ('last_error', '');
