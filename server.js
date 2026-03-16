require("dotenv").config();
const axios = require("axios");
const path = require("path");
const fsStream = require("fs");
const fs = require("fs/promises");
const crypto = require("crypto");
const dns = require("dns/promises");
const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const OpenAI = require("openai");
let whois = null;
try {
  whois = require("whois-json");
} catch (err) {
  // Optional dependency: WHOIS enrichment is skipped when unavailable.
}

const app = express();
const dataDir = path.join(__dirname, "data");
const analyzerCsvPath = path.join(dataDir, "analyzer_logs.csv");
const analyzerJsonPath = path.join(dataDir, "analyzer_logs.json");
const agentCasesJsonPath = path.join(dataDir, "agent_cases.json");
const adminExportKey = (process.env.ADMIN_EXPORT_KEY || "change-me").trim();
const appAdminEmail = (process.env.APP_ADMIN_EMAIL || "darshana@gmail.com").trim().toLowerCase();
const appAdminPassword = (process.env.APP_ADMIN_PASSWORD || "dr12345").trim();
const openaiApiKey = (process.env.OPENAI_API_KEY || "").trim();
const openaiModel = (process.env.OPENAI_MODEL || "gpt-4.1-mini").trim();
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});
const openaiClient = openaiApiKey ? new OpenAI({ apiKey: openaiApiKey }) : null;
const virusTotalApiKey = (process.env.VIRUSTOTAL_API_KEY || "").trim();
const googleSafeBrowsingApiKey = (process.env.GOOGLE_SAFE_BROWSING_API_KEY || "").trim();
const googleSafeBrowsingApiUrl = (process.env.GOOGLE_SAFE_BROWSING_API_URL || "https://safebrowsing.googleapis.com/v4/threatMatches:find").trim();
const threatApiTimeoutMs = Math.max(2000, Number(process.env.THREAT_API_TIMEOUT_MS || 7000));
const githubThreatFeedUrl = (process.env.GITHUB_THREAT_FEED_URL || "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/phishing-onlydomains.txt").trim();
const githubThreatFeedTtlMs = Math.max(60 * 1000, Number(process.env.GITHUB_THREAT_FEED_TTL_MS || 30 * 60 * 1000));
const githubApkThreatFeedUrl = (process.env.GITHUB_APK_THREAT_FEED_URL || "https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/hash-iocs.txt").trim();
const githubApkThreatFeedTtlMs = Math.max(60 * 1000, Number(process.env.GITHUB_APK_THREAT_FEED_TTL_MS || 30 * 60 * 1000));
const githubEmailThreatFeedUrl = (process.env.GITHUB_EMAIL_THREAT_FEED_URL || "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/phishing-onlydomains.txt").trim();
const githubEmailThreatFeedTtlMs = Math.max(60 * 1000, Number(process.env.GITHUB_EMAIL_THREAT_FEED_TTL_MS || 30 * 60 * 1000));
const threatIntelRealtime = /^(1|true|yes)$/i.test(String(process.env.THREAT_INTEL_REALTIME || "").trim());
const threatIntelStrictMode = /^(1|true|yes)$/i.test(String(process.env.THREAT_INTEL_STRICT_MODE || "").trim());
const agentMaxSteps = Math.max(3, Math.min(8, Number(process.env.AGENT_MAX_STEPS || 6)));
const agentToolTimeoutMs = Math.max(3000, Number(process.env.AGENT_TOOL_TIMEOUT_MS || 12000));
const agentRateWindowMs = 60 * 1000;
const agentRateLimitPerWindow = Math.max(2, Number(process.env.AGENT_RATE_LIMIT || 8));
const phishingQuestions = new Map();
const phishingTimelineRuns = new Map();
const passwordQuestions = new Map();
const safeLinkQuestions = new Map();
const malwareQuestions = new Map();
const malwareChainRuns = new Map();
const PHISHING_TTL_MS = 20 * 60 * 1000;
let githubThreatFeedCache = {
  loadedAt: 0,
  domains: new Set(),
  urls: new Set(),
  loadError: ""
};
let githubApkThreatFeedCache = {
  loadedAt: 0,
  hashes: new Set(),
  packages: new Set(),
  loadError: ""
};
let githubEmailThreatFeedCache = {
  loadedAt: 0,
  domains: new Set(),
  urls: new Set(),
  loadError: ""
};
const agentRateWindowByEmail = new Map();


const allowedGameKeys = new Set([
  "url",
  "apk",
  "email",
  "password",
  "social-engineering",
  "incident-response"
]);
const usersTable = "users";
const loginAuditTable = "login_audit";
const emailRegex = /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i;
const disposableEmailDomains = new Set([
  "mailinator.com",
  "guerrillamail.com",
  "10minutemail.com",
  "tempmail.com",
  "yopmail.com",
  "trashmail.com"
]);
const dbHost = process.env.DB_HOST || "localhost";
const dbPort = Number(process.env.DB_PORT || 3306);
const dbUser = process.env.DB_USER || "root";
const dbPassword = process.env.DB_PASSWORD || "";
const dbName = process.env.DB_NAME || "indexdb";

const bootstrapPool = mysql.createPool({
  host: dbHost,
  port: dbPort,
  user: dbUser,
  password: dbPassword,
  waitForConnections: true,
  connectionLimit: 2,
  queueLimit: 0
});

const pool = mysql.createPool({
  host: dbHost,
  port: dbPort,
  user: dbUser,
  password: dbPassword,
  database: dbName,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

async function ensureDatabaseExists() {
  await bootstrapPool.query("CREATE DATABASE IF NOT EXISTS ??", [dbName]);
  await bootstrapPool.end();
}

app.use(express.json());
app.use(express.static(path.join(__dirname)));

app.use((req, res, next) => {
  if (req.path === "/phishing-hunter" || req.path.startsWith("/api/game/")) {
    return res.status(404).json({ message: "Game module has been removed from this project." });
  }
  return next();
});

app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "html", "index1.html"));
});
app.get("/url-challenge", (_req, res) => {
  res.sendFile(path.join(__dirname, "game", "url-challenge-cybear.html"));
});
app.get("/apk-challenge", (_req, res) => {
  res.sendFile(path.join(__dirname, "game", "apk.html"));
});
app.get("/email-challenge", (_req, res) => {
  res.sendFile(path.join(__dirname, "game", "email.html"));
});
app.get("/password-challenge", (_req, res) => {
  res.sendFile(path.join(__dirname, "game", "password.html"));
});
app.get("/social-engineering-challenge", (_req, res) => {
  res.sendFile(path.join(__dirname, "game", "social-engineering.html"));
});
app.get("/incident-response-challenge", (_req, res) => {
  res.sendFile(path.join(__dirname, "game", "incident-response.html"));
});
async function ensureUsersTable() {
  const createSql = `
    CREATE TABLE IF NOT EXISTS \`${usersTable}\` (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(120),
      name VARCHAR(120),
      email VARCHAR(190),
      password VARCHAR(255),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;
  await pool.query(createSql);

  const [existingColumns] = await pool.query(`SHOW COLUMNS FROM \`${usersTable}\``);
  const existing = new Set(existingColumns.map((c) => c.Field.toLowerCase()));
  if (!existing.has("username")) {
    await pool.query(`ALTER TABLE \`${usersTable}\` ADD COLUMN username VARCHAR(120)`);
  }
  if (!existing.has("name")) {
    await pool.query(`ALTER TABLE \`${usersTable}\` ADD COLUMN name VARCHAR(120)`);
  }
  if (!existing.has("email")) {
    await pool.query(`ALTER TABLE \`${usersTable}\` ADD COLUMN email VARCHAR(190)`);
  }
  if (!existing.has("password")) {
    await pool.query(`ALTER TABLE \`${usersTable}\` ADD COLUMN password VARCHAR(255)`);
  }
  if (!existing.has("created_at")) {
    await pool.query(`ALTER TABLE \`${usersTable}\` ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`);
  }

  const [indexes] = await pool.query(`SHOW INDEX FROM \`${usersTable}\` WHERE Key_name = 'ux_users_email'`);
  if (indexes.length === 0) {
    try {
      await pool.query(`CREATE UNIQUE INDEX ux_users_email ON \`${usersTable}\` (email)`);
    } catch (err) {
      // If duplicate emails already exist in old data, app-level checks still prevent new duplicates.
      if (err.code !== "ER_DUP_ENTRY") {
        throw err;
      }
    }
  }
}

async function ensureLoginAuditTable() {
  const createSql = `
    CREATE TABLE IF NOT EXISTS \`${loginAuditTable}\` (
      id BIGINT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NULL,
      user_email VARCHAR(190) NOT NULL,
      user_name VARCHAR(120),
      ip_address VARCHAR(64),
      forwarded_for VARCHAR(255),
      request_origin VARCHAR(255),
      user_agent VARCHAR(255),
      login_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      user_login_date DATE NULL,
      user_login_time TIME NULL,
      user_timezone VARCHAR(80) NULL,
      INDEX idx_login_audit_user_email (user_email),
      INDEX idx_login_audit_login_at (login_at)
    )
  `;
  await pool.query(createSql);

  const [existingColumns] = await pool.query(`SHOW COLUMNS FROM \`${loginAuditTable}\``);
  const existingSet = new Set(existingColumns.map((c) => String(c.Field || "").toLowerCase()));

  if (!existingSet.has("user_login_date")) {
    await pool.query(`ALTER TABLE \`${loginAuditTable}\` ADD COLUMN user_login_date DATE NULL`);
  }
  if (!existingSet.has("user_login_time")) {
    await pool.query(`ALTER TABLE \`${loginAuditTable}\` ADD COLUMN user_login_time TIME NULL`);
  }
  if (!existingSet.has("user_timezone")) {
    await pool.query(`ALTER TABLE \`${loginAuditTable}\` ADD COLUMN user_timezone VARCHAR(80) NULL`);
  }
}

function getRequestIp(req) {
  const forwarded = String(req.headers["x-forwarded-for"] || "").trim();
  const firstForwardedIp = forwarded.split(",")[0].trim();
  const rawIp = firstForwardedIp || req.socket?.remoteAddress || "";
  if (rawIp.startsWith("::ffff:")) {
    return rawIp.slice(7);
  }
  return rawIp;
}

function parseUserLoginMeta(loginMeta) {
  const rawDate = String(loginMeta?.clientLoginDate || "").trim();
  const rawTime = String(loginMeta?.clientLoginTime || "").trim();
  const rawTz = String(loginMeta?.clientTimeZone || "").trim();

  const isDateValid = /^\d{4}-\d{2}-\d{2}$/.test(rawDate);
  const isTimeValid = /^\d{2}:\d{2}:\d{2}$/.test(rawTime);

  return {
    userLoginDate: isDateValid ? rawDate : null,
    userLoginTime: isTimeValid ? rawTime : null,
    userTimezone: rawTz ? rawTz.slice(0, 80) : null
  };
}

async function recordLoginAudit(req, user, loginMeta = {}) {
  const forwardedFor = String(req.headers["x-forwarded-for"] || "").slice(0, 255);
  const requestOrigin = String(req.headers.origin || req.headers.referer || "").slice(0, 255);
  const userAgent = String(req.headers["user-agent"] || "").slice(0, 255);
  const ipAddress = getRequestIp(req).slice(0, 64);
  const userName = String(user.name || user.username || "").slice(0, 120);
  const { userLoginDate, userLoginTime, userTimezone } = parseUserLoginMeta(loginMeta);

  await pool.query(
    `INSERT INTO \`${loginAuditTable}\`
      (user_id, user_email, user_name, ip_address, forwarded_for, request_origin, user_agent, user_login_date, user_login_time, user_timezone)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      user.id ?? null,
      String(user.email || "").toLowerCase(),
      userName,
      ipAddress,
      forwardedFor,
      requestOrigin,
      userAgent,
      userLoginDate,
      userLoginTime,
      userTimezone
    ]
  );
}

async function recordLoginAuditSafe(req, user, loginMeta = {}) {
  try {
    await recordLoginAudit(req, user, loginMeta);
  } catch (err) {
    if (err?.code === "ER_NO_SUCH_TABLE") {
      try {
        await ensureLoginAuditTable();
        await recordLoginAudit(req, user, loginMeta);
        return;
      } catch (retryErr) {
        console.error("Login audit retry failed:", retryErr.code || "UNKNOWN", retryErr.message || "");
        return;
      }
    }
    console.error("Login audit failed:", err.code || "UNKNOWN", err.message || "");
  }
}

function isEmailFormatValid(email) {
  return emailRegex.test(String(email || "").trim());
}

function isDisposableEmailDomain(email) {
  const domain = String(email || "").split("@")[1] || "";
  return disposableEmailDomains.has(domain.toLowerCase());
}

async function hasMxRecords(email) {
  const domain = String(email || "").split("@")[1] || "";
  if (!domain) return false;
  try {
    const records = await dns.resolveMx(domain);
    return Array.isArray(records) && records.length > 0;
  } catch (err) {
    const code = String(err?.code || "").toUpperCase();
    const hardInvalidCodes = new Set(["ENOTFOUND", "ENODATA", "EAI_NONAME", "EBADNAME"]);
    if (hardInvalidCodes.has(code)) {
      return false;
    }
  }

  // Fallback: some valid domains rely on A/AAAA routing instead of explicit MX.
  try {
    const [aResult, aaaaResult] = await Promise.allSettled([
      dns.resolve4(domain),
      dns.resolve6(domain)
    ]);
    const hasA = aResult.status === "fulfilled" && Array.isArray(aResult.value) && aResult.value.length > 0;
    const hasAAAA = aaaaResult.status === "fulfilled" && Array.isArray(aaaaResult.value) && aaaaResult.value.length > 0;
    if (hasA || hasAAAA) {
      return true;
    }
  } catch {
    // no-op
  }

  return false;
}

async function ensureGameScoresTable() {
  const createSql = `
    CREATE TABLE IF NOT EXISTS game_scores (
      id BIGINT AUTO_INCREMENT PRIMARY KEY,
      user_name VARCHAR(120) NOT NULL,
      user_email VARCHAR(190) NOT NULL,
      game_key VARCHAR(64) NOT NULL,
      score INT NOT NULL,
      accuracy DECIMAL(5,2) NOT NULL DEFAULT 0,
      correct_count INT NOT NULL DEFAULT 0,
      total_questions INT NOT NULL DEFAULT 0,
      duration_seconds INT NOT NULL DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_game_scores_game_key (game_key),
      INDEX idx_game_scores_user_email (user_email),
      INDEX idx_game_scores_created_at (created_at)
    )
  `;
  await pool.query(createSql);
}

async function ensureLeaderboardTable() {
  const createSql = `
    CREATE TABLE IF NOT EXISTS leaderboard (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(100) NOT NULL,
      email VARCHAR(150),
      score INT DEFAULT 0,
      scans_completed INT DEFAULT 0,
      threats_detected INT DEFAULT 0,
      source_game_score_id BIGINT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;
  await pool.query(createSql);

  const [existingColumns] = await pool.query("SHOW COLUMNS FROM leaderboard");
  const columnSet = new Set((existingColumns || []).map((c) => String(c.Field || "").toLowerCase()));
  if (!columnSet.has("source_game_score_id")) {
    await pool.query("ALTER TABLE leaderboard ADD COLUMN source_game_score_id BIGINT NULL");
  }

  const [emailIndexes] = await pool.query("SHOW INDEX FROM leaderboard WHERE Key_name = 'ux_leaderboard_email'");
  if ((emailIndexes || []).length > 0) {
    try {
      await pool.query("DROP INDEX ux_leaderboard_email ON leaderboard");
    } catch (err) {
      if (err?.code !== "ER_CANT_DROP_FIELD_OR_KEY" && err?.code !== "ER_DROP_INDEX_FK") {
        throw err;
      }
    }
  }

  const [sourceIndexes] = await pool.query("SHOW INDEX FROM leaderboard WHERE Key_name = 'ux_leaderboard_source_game_score_id'");
  if ((sourceIndexes || []).length === 0) {
    await pool.query("CREATE UNIQUE INDEX ux_leaderboard_source_game_score_id ON leaderboard (source_game_score_id)");
  }
}

async function backfillLeaderboardFromGameScores() {
  try {
    await pool.query(
      `INSERT INTO leaderboard (username, email, score, scans_completed, threats_detected, source_game_score_id, created_at)
       SELECT
         COALESCE(NULLIF(u.username, ""), NULLIF(gs.user_name, ""), "User") AS username,
         gs.user_email AS email,
         COALESCE(gs.score, 0) AS score,
         COALESCE(gs.total_questions, 0) AS scans_completed,
         COALESCE(gs.correct_count, 0) AS threats_detected,
         gs.id AS source_game_score_id,
         gs.created_at AS created_at
       FROM game_scores gs
       LEFT JOIN \`${usersTable}\` u ON LOWER(COALESCE(u.email, "")) = gs.user_email
       LEFT JOIN leaderboard lb ON lb.source_game_score_id = gs.id
       WHERE gs.user_email IS NOT NULL AND gs.user_email <> ""
         AND lb.id IS NULL
       ORDER BY gs.created_at ASC`
    );
  } catch (err) {
    console.error("leaderboard backfill failed:", err.code || "UNKNOWN", err.message || "");
  }
}

async function ensureAnalysisHistoryTable() {
  const createSql = `
    CREATE TABLE IF NOT EXISTS analysis_history (
      id BIGINT AUTO_INCREMENT PRIMARY KEY,
      type VARCHAR(32) NOT NULL,
      input_data LONGTEXT NOT NULL,
      result LONGTEXT NOT NULL,
      risk_score INT NOT NULL DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_analysis_history_type (type),
      INDEX idx_analysis_history_created_at (created_at)
    )
  `;
  await pool.query(createSql);
}

async function saveAnalysisHistory(type, inputData, result, riskScore) {
  await pool.query(
    `INSERT INTO analysis_history (type, input_data, result, risk_score)
     VALUES (?, ?, ?, ?)`,
    [
      String(type || "").trim().toLowerCase(),
      JSON.stringify(inputData ?? {}),
      JSON.stringify(result ?? {}),
      Number(riskScore || 0)
    ]
  );
}

async function saveAnalysisHistorySafe(type, inputData, result, riskScore) {
  try {
    await saveAnalysisHistory(type, inputData, result, riskScore);
  } catch (err) {
    if (err?.code === "ER_NO_SUCH_TABLE") {
      try {
        await ensureAnalysisHistoryTable();
        await saveAnalysisHistory(type, inputData, result, riskScore);
        return;
      } catch (retryErr) {
        console.error("analysis_history retry failed:", retryErr.code || "UNKNOWN", retryErr.message || "");
        return;
      }
    }
    console.error("analysis_history save failed:", err.code || "UNKNOWN", err.message || "");
  }
}

function csvEscape(value) {
  const text = String(value ?? "");
  if (/[",\n]/.test(text)) {
    return `"${text.replace(/"/g, '""')}"`;
  }
  return text;
}

function generateLogId() {
  return `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
}

async function readAnalyzerLogs() {
  const raw = await fs.readFile(analyzerJsonPath, "utf8");
  const parsed = JSON.parse(raw);
  if (!Array.isArray(parsed)) return [];
  return parsed;
}

async function writeAnalyzerLogs(logs) {
  await fs.writeFile(analyzerJsonPath, JSON.stringify(logs), "utf8");
  const header = "timestamp,type,user_name,user_email,details\n";
  const lines = logs.map((entry) => [
    entry.timestamp,
    entry.type,
    entry.user_name,
    entry.user_email,
    entry.details
  ].map(csvEscape).join(","));
  const content = header + (lines.length ? `${lines.join("\n")}\n` : "");
  await fs.writeFile(analyzerCsvPath, content, "utf8");
}

function normalizeUserEmail(email) {
  const value = String(email || "").trim().toLowerCase();
  return value || "guest@local";
}

function normalizeUrl(raw) {
  const input = String(raw || "").trim();
  if (!input) return null;
  try {
    return new URL(input);
  } catch {
    try {
      return new URL(`https://${input}`);
    } catch {
      return null;
    }
  }
}

function normalizeThreatFeedToken(raw) {
  const token = String(raw || "").trim().toLowerCase();
  if (!token) return null;

  const cleaned = token.replace(/^0\.0\.0\.0\s+/, "").replace(/^127\.0\.0\.1\s+/, "");
  if (!cleaned || cleaned === "localhost") return null;
  if (cleaned.startsWith("#")) return null;

  if (cleaned.startsWith("http://") || cleaned.startsWith("https://")) {
    const parsed = normalizeUrl(cleaned);
    if (!parsed) return null;
    return {
      type: "url",
      value: parsed.href.toLowerCase().replace(/\/$/, ""),
      host: parsed.hostname.toLowerCase()
    };
  }

  const host = cleaned.replace(/^\*\./, "").replace(/\.$/, "");
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(host)) return null;
  return { type: "domain", value: host };
}

function shouldUseThreatFeedCache(cacheLoadedAt, ttlMs) {
  if (threatIntelRealtime) return false;
  return (Date.now() - cacheLoadedAt) < ttlMs;
}

function normalizeApkThreatFeedToken(raw) {
  const token = String(raw || "").trim().toLowerCase();
  if (!token) return null;
  if (token.startsWith("#")) return null;

  const cleaned = token
    .replace(/^sha256[:=\s]+/, "")
    .replace(/^hash[:=\s]+/, "")
    .replace(/^\"|\"$/g, "");
  if (!cleaned) return null;

  if (/^[a-f0-9]{64}$/.test(cleaned)) {
    return { type: "hash", value: cleaned };
  }
  if (/^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,}$/i.test(cleaned)) {
    return { type: "package", value: cleaned };
  }
  return null;
}

async function loadGithubThreatFeed() {
  if (!githubThreatFeedUrl) return githubThreatFeedCache;

  if (shouldUseThreatFeedCache(githubThreatFeedCache.loadedAt, githubThreatFeedTtlMs)) {
    return githubThreatFeedCache;
  }

  const now = Date.now();
  try {
    const res = await fetch(githubThreatFeedUrl, { method: "GET" });
    if (!res.ok) {
      throw new Error(`Threat feed status ${res.status}`);
    }

    const raw = await res.text();
    const domains = new Set();
    const urls = new Set();
    const lines = raw.split(/\r?\n/);

    for (const line of lines) {
      const segment = String(line).split("#")[0].trim();
      if (!segment) continue;

      const token = segment.includes(" ") ? segment.split(/\s+/).pop() : segment;
      const normalized = normalizeThreatFeedToken(token);
      if (!normalized) continue;

      if (normalized.type === "url") {
        urls.add(normalized.value);
        domains.add(normalized.host);
      } else {
        domains.add(normalized.value);
      }
    }

    githubThreatFeedCache = {
      loadedAt: now,
      domains,
      urls,
      loadError: ""
    };
  } catch (err) {
    githubThreatFeedCache = {
      ...githubThreatFeedCache,
      loadedAt: now,
      loadError: String(err?.message || err || "Unknown threat feed error")
    };
  }

  return githubThreatFeedCache;
}

async function loadGithubApkThreatFeed() {
  if (!githubApkThreatFeedUrl) return githubApkThreatFeedCache;

  if (shouldUseThreatFeedCache(githubApkThreatFeedCache.loadedAt, githubApkThreatFeedTtlMs)) {
    return githubApkThreatFeedCache;
  }

  const now = Date.now();
  try {
    const res = await fetch(githubApkThreatFeedUrl, { method: "GET" });
    if (!res.ok) {
      throw new Error(`APK threat feed status ${res.status}`);
    }

    const raw = await res.text();
    const hashes = new Set();
    const packages = new Set();
    const lines = raw.split(/\r?\n/);

    for (const line of lines) {
      const segment = String(line).split("#")[0].trim();
      if (!segment) continue;

      const parts = segment.split(/[,\s\t]+/).filter(Boolean);
      for (const part of parts) {
        const normalized = normalizeApkThreatFeedToken(part);
        if (!normalized) continue;
        if (normalized.type === "hash") {
          hashes.add(normalized.value);
        } else {
          packages.add(normalized.value);
        }
      }
    }

    githubApkThreatFeedCache = {
      loadedAt: now,
      hashes,
      packages,
      loadError: ""
    };
  } catch (err) {
    githubApkThreatFeedCache = {
      ...githubApkThreatFeedCache,
      loadedAt: now,
      loadError: String(err?.message || err || "Unknown APK threat feed error")
    };
  }

  return githubApkThreatFeedCache;
}

async function loadGithubEmailThreatFeed() {
  if (!githubEmailThreatFeedUrl) return githubEmailThreatFeedCache;

  if (shouldUseThreatFeedCache(githubEmailThreatFeedCache.loadedAt, githubEmailThreatFeedTtlMs)) {
    return githubEmailThreatFeedCache;
  }

  const now = Date.now();
  try {
    const res = await fetch(githubEmailThreatFeedUrl, { method: "GET" });
    if (!res.ok) {
      throw new Error(`Email threat feed status ${res.status}`);
    }

    const raw = await res.text();
    const domains = new Set();
    const urls = new Set();
    const lines = raw.split(/\r?\n/);

    for (const line of lines) {
      const segment = String(line).split("#")[0].trim();
      if (!segment) continue;

      const token = segment.includes(" ") ? segment.split(/\s+/).pop() : segment;
      const normalized = normalizeThreatFeedToken(token);
      if (!normalized) continue;

      if (normalized.type === "url") {
        urls.add(normalized.value);
        domains.add(normalized.host);
      } else {
        domains.add(normalized.value);
      }
    }

    githubEmailThreatFeedCache = {
      loadedAt: now,
      domains,
      urls,
      loadError: ""
    };
  } catch (err) {
    githubEmailThreatFeedCache = {
      ...githubEmailThreatFeedCache,
      loadedAt: now,
      loadError: String(err?.message || err || "Unknown email threat feed error")
    };
  }

  return githubEmailThreatFeedCache;
}

function findThreatFeedDomainMatch(hostname, domainSet) {
  const host = String(hostname || "").toLowerCase();
  if (!host) return null;
  const parts = host.split(".");
  for (let i = 0; i <= parts.length - 2; i += 1) {
    const candidate = parts.slice(i).join(".");
    if (domainSet.has(candidate)) {
      return candidate;
    }
  }
  return null;
}

function extractEmailThreatCandidates(emailTextValue) {
  const text = String(emailTextValue || "");
  const domains = new Set();
  const urls = new Set();

  const fromHeader = (text.match(/^from:\s*(.+)$/im) || [])[1] || "";
  const replyHeader = (text.match(/^reply-to:\s*(.+)$/im) || [])[1] || "";
  const fromDomain = (fromHeader.match(/@([a-z0-9.-]+\.[a-z]{2,})/i) || [])[1] || "";
  const replyDomain = (replyHeader.match(/@([a-z0-9.-]+\.[a-z]{2,})/i) || [])[1] || "";
  if (fromDomain) domains.add(fromDomain.toLowerCase());
  if (replyDomain) domains.add(replyDomain.toLowerCase());

  const linkMatches = text.match(/https?:\/\/[^\s)>"']+/gi) || [];
  for (const rawUrl of linkMatches) {
    const parsed = normalizeUrl(rawUrl);
    if (!parsed) continue;
    urls.add(parsed.href.toLowerCase().replace(/\/$/, ""));
    domains.add(parsed.hostname.toLowerCase());
  }

  return { domains: [...domains], urls: [...urls] };
}

async function evaluateGithubThreatIntel(urlValue) {
  const parsed = normalizeUrl(urlValue);
  if (!parsed) {
    return { matched: false, source: githubThreatFeedUrl };
  }

  const feed = await loadGithubThreatFeed();
  if (!feed || (!feed.domains.size && !feed.urls.size)) {
    return { matched: false, source: githubThreatFeedUrl, error: feed?.loadError || "" };
  }

  const normalizedHref = parsed.href.toLowerCase().replace(/\/$/, "");
  if (feed.urls.has(normalizedHref)) {
    return {
      matched: true,
      matchType: "exact-url",
      indicator: normalizedHref,
      source: githubThreatFeedUrl
    };
  }

  const domainMatch = findThreatFeedDomainMatch(parsed.hostname, feed.domains);
  if (domainMatch) {
    return {
      matched: true,
      matchType: "domain",
      indicator: domainMatch,
      source: githubThreatFeedUrl
    };
  }

  return { matched: false, source: githubThreatFeedUrl };
}

async function evaluateGithubApkThreatIntel(apkValue) {
  const input = String(apkValue || "").trim().toLowerCase();
  if (!input) {
    return { matched: false, source: githubApkThreatFeedUrl };
  }

  const feed = await loadGithubApkThreatFeed();
  if (!feed || (!feed.hashes.size && !feed.packages.size)) {
    return { matched: false, source: githubApkThreatFeedUrl, error: feed?.loadError || "" };
  }

  if (/^[a-f0-9]{64}$/.test(input) && feed.hashes.has(input)) {
    return {
      matched: true,
      matchType: "sha256",
      indicator: input,
      source: githubApkThreatFeedUrl
    };
  }

  if (feed.packages.has(input)) {
    return {
      matched: true,
      matchType: "package",
      indicator: input,
      source: githubApkThreatFeedUrl
    };
  }

  return { matched: false, source: githubApkThreatFeedUrl };
}

async function evaluateGithubEmailThreatIntel(emailTextValue) {
  const feed = await loadGithubEmailThreatFeed();
  if (!feed || (!feed.domains.size && !feed.urls.size)) {
    return { matched: false, source: githubEmailThreatFeedUrl, error: feed?.loadError || "" };
  }

  const candidates = extractEmailThreatCandidates(emailTextValue);
  for (const candidateUrl of candidates.urls) {
    if (feed.urls.has(candidateUrl)) {
      return {
        matched: true,
        matchType: "exact-url",
        indicator: candidateUrl,
        source: githubEmailThreatFeedUrl
      };
    }
  }

  for (const domain of candidates.domains) {
    const domainMatch = findThreatFeedDomainMatch(domain, feed.domains);
    if (domainMatch) {
      return {
        matched: true,
        matchType: "domain",
        indicator: domainMatch,
        source: githubEmailThreatFeedUrl
      };
    }
  }

  return { matched: false, source: githubEmailThreatFeedUrl };
}

function mergeGithubApkIntelRisk(result, intel) {
  if (!intel?.matched) return result;

  const riskScore = clampPercent(Math.max(result.riskScore + 38, 92));
  const confidence = clampPercent(Math.max(result.confidence, 90));
  const riskLevel = riskScore >= 70 ? "high" : riskScore >= 40 ? "medium" : "low";

  const factors = [
    { name: "GitHub APK threat feed match", score: 99 },
    ...(Array.isArray(result.factors) ? result.factors : [])
  ].slice(0, 6);

  const intelSummary = intel.matchType === "sha256"
    ? "APK SHA256 matched configured GitHub threat feed."
    : `APK package matched configured GitHub threat feed (${intel.indicator}).`;

  return {
    ...result,
    riskScore,
    confidence,
    riskLevel,
    summary: `${intelSummary} ${String(result.summary || "").trim()}`.trim().slice(0, 280),
    factors
  };
}

function mergeGithubEmailIntelRisk(result, intel) {
  if (!intel?.matched) return result;

  const riskScore = clampPercent(Math.max(result.riskScore + 34, 90));
  const confidence = clampPercent(Math.max(result.confidence, 89));
  const riskLevel = riskScore >= 70 ? "high" : riskScore >= 40 ? "medium" : "low";

  const factors = [
    { name: "GitHub email threat feed match", score: 98 },
    ...(Array.isArray(result.factors) ? result.factors : [])
  ].slice(0, 6);

  const intelSummary = intel.matchType === "exact-url"
    ? "Email contains a URL matched in configured GitHub threat feed."
    : `Email sender/link domain matched configured GitHub threat feed (${intel.indicator}).`;

  return {
    ...result,
    riskScore,
    confidence,
    riskLevel,
    summary: `${intelSummary} ${String(result.summary || "").trim()}`.trim().slice(0, 280),
    factors
  };
}

function clampPercent(value) {
  return Math.max(0, Math.min(100, Math.round(Number(value) || 0)));
}

function normalizeRiskShape(input, fallback) {
  const riskScore = clampPercent(input?.riskScore);
  const confidence = clampPercent(input?.confidence);
  const riskLevelRaw = String(input?.riskLevel || "").toLowerCase();
  const riskLevel = ["low", "medium", "high"].includes(riskLevelRaw)
    ? riskLevelRaw
    : (riskScore >= 70 ? "high" : riskScore >= 40 ? "medium" : "low");
  const summary = String(input?.summary || fallback.summary || "").slice(0, 280);
  const factors = Array.isArray(input?.factors) && input.factors.length > 0
    ? input.factors.slice(0, 6).map((f) => ({
      name: String(f?.name || "Signal").slice(0, 60),
      score: clampPercent(f?.score)
    }))
    : (fallback.factors || []);

  return {
    riskScore: riskScore || fallback.riskScore || 0,
    confidence: confidence || fallback.confidence || 0,
    riskLevel,
    summary,
    factors
  };
}

function extractFirstJsonObject(text) {
  const raw = String(text || "").trim();
  if (!raw) return null;
  const start = raw.indexOf("{");
  const end = raw.lastIndexOf("}");
  if (start < 0 || end < 0 || end <= start) return null;
  const candidate = raw.slice(start, end + 1);
  try {
    return JSON.parse(candidate);
  } catch {
    return null;
  }
}

async function callLlmRiskAssessment(prompt, fallback) {
  if (!openaiApiKey) return fallback;

  try {
    const response = await fetch("https://api.openai.com/v1/responses", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${openaiApiKey}`
      },
      body: JSON.stringify({
        model: openaiModel,
        input: prompt,
        temperature: 0.05
      })
    });

    if (!response.ok) {
      return fallback;
    }

    const data = await response.json();
    const parsed = extractFirstJsonObject(data.output_text || "");
    if (!parsed) {
      return fallback;
    }

    return normalizeRiskShape(parsed, fallback);
  } catch {
    return fallback;
  }
}

function blendRisk(primary, secondary, primaryWeight = 0.65) {
  const secondaryWeight = 1 - primaryWeight;
  const riskScore = clampPercent((primary.riskScore * primaryWeight) + (secondary.riskScore * secondaryWeight));
  const confidence = clampPercent((primary.confidence * primaryWeight) + (secondary.confidence * secondaryWeight));
  const riskLevel = riskScore >= 70 ? "high" : riskScore >= 40 ? "medium" : "low";

  const factors = (Array.isArray(primary.factors) ? primary.factors : []).map((f) => {
    const match = (secondary.factors || []).find((s) => String(s.name).toLowerCase() === String(f.name).toLowerCase());
    return {
      name: f.name,
      score: clampPercent((f.score * primaryWeight) + ((match?.score || 0) * secondaryWeight))
    };
  });

  return {
    riskScore,
    confidence,
    riskLevel,
    summary: primary.summary || secondary.summary || "Risk analysis completed.",
    factors: factors.length ? factors : primary.factors
  };
}

async function fetchWithTimeout(url, options = {}, timeoutMs = threatApiTimeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function scanURL(url) {
  const vtResponse = await axios.post(
    "https://www.virustotal.com/api/v3/urls",
    new URLSearchParams({ url }),
    {
      headers: {
        "x-apikey": process.env.VIRUSTOTAL_API_KEY,
        "content-type": "application/x-www-form-urlencoded"
      }
    }
  );

  const analysisId = vtResponse.data.data.id;
  let lastData = null;

  for (let i = 0; i < 5; i += 1) {
    const result = await axios.get(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      {
        headers: {
          "x-apikey": process.env.VIRUSTOTAL_API_KEY
        }
      }
    );
    lastData = result.data;
    const status = String(result?.data?.data?.attributes?.status || "").toLowerCase();
    if (status === "completed") break;
    if (i < 4) {
      await new Promise((resolve) => setTimeout(resolve, 1200));
    }
  }

  return lastData;
}

async function googleCheck(url) {
  const response = await axios.post(
    `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GOOGLE_SAFE_BROWSING_API_KEY}`,
    {
      client: {
        clientId: "cyber-shield",
        clientVersion: "1.0"
      },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }]
      }
    }
  );

  return response.data;
}

async function urlAgent(url) {
  const vt = await scanURL(url);
  const google = await googleCheck(url);

  return {
    virustotal: vt,
    googleSafe: google
  };
}

async function aiAnalysis(scanData) {
  const prompt = `
You are a cybersecurity expert.

Analyze the following scan results and return:

1. Risk Score (0-100)
2. Threat Type
3. Short Explanation

Scan Data:
${JSON.stringify(scanData)}
`;

  const response = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: prompt }]
  });

  return response.choices[0].message.content;
}

async function securityAgent(url) {
  const scanData = await urlAgent(url);

  const aiResult = await aiAnalysis(scanData);

  return {
    scanData,
    aiResult
  };
}

async function scanAPK(filePath) {
  const formData = new FormData();
  formData.append("file", fsStream.createReadStream(filePath));

  const response = await axios.post(
    "https://www.virustotal.com/api/v3/files",
    formData,
    {
      headers: {
        "x-apikey": process.env.VIRUSTOTAL_API_KEY,
        ...formData.getHeaders()
      }
    }
  );

  return response.data;
}

async function checkPhishTank(url) {
  const axios = require("axios");

  const response = await axios.post(
    "https://checkurl.phishtank.com/checkurl/",
    `url=${encodeURIComponent(url)}&format=json`,
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      }
    }
  );

  return response.data;
}

async function checkURLHaus(url) {
  const axios = require("axios");

  const response = await axios.post(
    "https://urlhaus-api.abuse.ch/v1/url/",
    { url: url }
  );

  return response.data;
}

async function aiDecision(data) {
  const response = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [
      {
        role: "user",
        content: `Analyze this security scan and return a risk score 0-100:

${JSON.stringify(data)}`
      }
    ]
  });

  return response.choices[0].message.content;
}

async function explainDangerousUrl(url) {
  const explanation = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [
      {
        role: "user",
        content: `Explain why this URL is dangerous:

${url}`
      }
    ]
  });

  return explanation.choices?.[0]?.message?.content || "";
}

async function checkIP(ip) {
  const axios = require("axios");

  const response = await axios.get(
    `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`,
    {
      headers: {
        Key: process.env.ABUSEIPDB_API_KEY,
        Accept: "application/json"
      }
    }
  );

  return response.data;
}

async function checkOpenPhish(url) {
  const axios = require("axios");

  const response = await axios.get(
    "https://openphish.com/feed.txt"
  );

  const phishingList = response.data.split("\n");

  return phishingList.includes(url);
}

async function threatAnalyzer(url) {
  const phishTank = await checkPhishTank(url);
  const urlHaus = await checkURLHaus(url);
  const google = await googleCheck(url);

  return {
    phishTank,
    urlHaus,
    google
  };
}

async function checkVirusTotal(url) {
  return scanURL(url);
}

function urlPatternAgent(url) {
  const input = String(url || "").trim();
  const parsed = normalizeUrl(input);
  const value = parsed ? `${parsed.hostname}${parsed.pathname}${parsed.search}`.toLowerCase() : input.toLowerCase();
  let score = 0;
  const reasons = [];

  const suspiciousWords = [
    "login",
    "verify",
    "secure",
    "update",
    "account",
    "bank",
    "paypal",
    "wallet",
    "coin",
    "generator",
    "bonus",
    "reward"
  ];

  suspiciousWords.forEach((word) => {
    if (value.includes(word)) {
      score += 8;
      reasons.push(`Contains suspicious token: ${word}`);
    }
  });

  if (input.includes("@")) {
    score += 20;
    reasons.push("Contains @ character in URL.");
  }
  if (input.includes("-")) {
    score += 5;
    reasons.push("Contains hyphen pattern often used in lookalike domains.");
  }

  if (parsed) {
    const host = String(parsed.hostname || "").toLowerCase();
    const labels = host.split(".").filter(Boolean);
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      score += 20;
      reasons.push("Uses raw IP address host.");
    }
    if (labels.length > 3) {
      score += 12;
      reasons.push("Excessive subdomain depth.");
    }
    if (host.length > 40) {
      score += 8;
      reasons.push("Unusually long hostname.");
    }
    if (host.includes("xn--")) {
      score += 15;
      reasons.push("Punycode hostname detected.");
    }
    const tld = labels[labels.length - 1] || "";
    if (["zip", "click", "top", "gq", "tk", "rest"].includes(tld)) {
      score += 10;
      reasons.push(`Higher-risk TLD: .${tld}`);
    }
  }

  return { patternScore: clampPercent(score), reasons };
}

async function domainAgent(url) {
  const parsed = normalizeUrl(url);
  if (!parsed) {
    return { domainRisk: 0, reasons: ["Invalid URL format for WHOIS lookup."], domain: "" };
  }
  const domain = parsed.hostname;

  let risk = 0;
  const reasons = [];

  if (!whois) {
    return {
      domainRisk: 0,
      reasons: ["WHOIS lookup unavailable: dependency could not be loaded."],
      domain
    };
  }

  try {
    const data = await whois(domain);
    const creationRaw = data?.creationDate || data?.created || data?.creation_date;
    const firstCreation = Array.isArray(creationRaw) ? creationRaw[0] : creationRaw;

    if (firstCreation) {
      const created = new Date(firstCreation);
      if (!Number.isNaN(created.getTime())) {
        const ageDays = (Date.now() - created.getTime()) / (1000 * 60 * 60 * 24);
        if (ageDays < 14) {
          risk += 35;
          reasons.push("Domain is very new (<14 days).");
        } else if (ageDays < 30) {
          risk += 25;
          reasons.push("Domain is new (<30 days).");
        } else if (ageDays < 90) {
          risk += 12;
          reasons.push("Domain age is relatively low (<90 days).");
        }
      }
    }

    if (String(data?.registrar || "").trim() === "") {
      risk += 6;
      reasons.push("Registrar metadata missing in WHOIS.");
    }
  } catch (err) {
    reasons.push(`WHOIS lookup unavailable: ${String(err?.message || err || "lookup failed")}`);
  }

  return { domainRisk: clampPercent(risk), reasons, domain };
}

async function threatFeedAgent(url) {
  const [vtRes, googleRes] = await Promise.allSettled([
    checkVirusTotal(url),
    googleCheck(url)
  ]);

  const vt = vtRes.status === "fulfilled" ? vtRes.value : null;
  const google = googleRes.status === "fulfilled" ? googleRes.value : null;

  let score = 0;
  const reasons = [];
  const sources = {
    virustotal: { available: vtRes.status === "fulfilled", malicious: 0, suspicious: 0 },
    googleSafeBrowsing: { available: googleRes.status === "fulfilled", matches: 0 }
  };

  if (google?.matches?.length) {
    const count = google.matches.length;
    score += Math.min(45, 20 + (count * 8));
    reasons.push(`Google Safe Browsing matched ${count} threat entry(s).`);
    sources.googleSafeBrowsing.matches = count;
  }

  const vtStats = vt?.data?.attributes?.stats || {};
  const malicious = Number(vtStats.malicious || 0);
  const suspicious = Number(vtStats.suspicious || 0);
  const harmless = Number(vtStats.harmless || 0);
  const undetected = Number(vtStats.undetected || 0);
  const total = malicious + suspicious + harmless + undetected;
  sources.virustotal.malicious = malicious;
  sources.virustotal.suspicious = suspicious;

  if (malicious > 0 || suspicious > 0) {
    const ratio = total > 0 ? (malicious + (suspicious * 0.7)) / total : 0;
    score += Math.min(50, Math.round((malicious * 10) + (suspicious * 6) + (ratio * 35)));
    reasons.push(`VirusTotal flagged malicious=${malicious}, suspicious=${suspicious}.`);
  } else if (vtRes.status === "fulfilled") {
    reasons.push("VirusTotal did not report malicious/suspicious detections.");
  }

  if (vtRes.status === "rejected") {
    reasons.push(`VirusTotal unavailable: ${String(vtRes.reason?.message || vtRes.reason || "request failed")}`);
  }
  if (googleRes.status === "rejected") {
    reasons.push(`Google Safe Browsing unavailable: ${String(googleRes.reason?.message || googleRes.reason || "request failed")}`);
  }

  return { threatScore: clampPercent(score), reasons, sources };
}

async function aiReasoner(data) {
  const prompt = `
You are a cybersecurity AI analyst.
Use only the provided evidence and output strict JSON.

Return:
{
  "riskScore": 0-100,
  "confidence": 0-100,
  "threatType": "phishing|malware|scam|benign|unknown",
  "explanation": "short explanation",
  "signals": ["signal 1", "signal 2", "signal 3"]
}

Evidence:
${JSON.stringify(data)}
`;

  const rawKey = String(process.env.OPENAI_API_KEY || "").trim();
  if (!rawKey || !rawKey.startsWith("sk-")) {
    return {
      available: false,
      riskScore: 0,
      confidence: 0,
      threatType: "unknown",
      explanation: "AI analysis unavailable: invalid or missing OpenAI API key.",
      signals: []
    };
  }

  try {
    const response = await openai.chat.completions.create({
      model: process.env.OPENAI_MODEL || "gpt-4.1-mini",
      messages: [{ role: "user", content: prompt }],
      temperature: 0.1,
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "risk_assessment",
          strict: true,
          schema: {
            type: "object",
            properties: {
              riskScore: { type: "number" },
              confidence: { type: "number" },
              threatType: { type: "string" },
              explanation: { type: "string" },
              signals: {
                type: "array",
                items: { type: "string" }
              }
            },
            required: ["riskScore", "confidence", "threatType", "explanation", "signals"],
            additionalProperties: false
          }
        }
      }
    });

    const raw = String(response?.choices?.[0]?.message?.content || "").trim();
    const parsed = extractFirstJsonObject(raw);
    if (!parsed) {
      return {
        available: false,
        riskScore: 0,
        confidence: 0,
        threatType: "unknown",
        explanation: "AI response was not structured JSON.",
        signals: []
      };
    }
    return {
      available: true,
      riskScore: clampPercent(Number(parsed.riskScore || 0)),
      confidence: clampPercent(Number(parsed.confidence || 0)),
      threatType: String(parsed.threatType || "unknown"),
      explanation: String(parsed.explanation || "No explanation"),
      signals: Array.isArray(parsed.signals) ? parsed.signals.map((s) => String(s)).slice(0, 6) : []
    };
  } catch (err) {
    const apiErr = String(err?.error?.message || err?.message || "OpenAI request failed");
    return {
      available: false,
      riskScore: 0,
      confidence: 0,
      threatType: "unknown",
      explanation: `AI analysis unavailable: ${apiErr}`,
      signals: []
    };
  }
}

async function autoAnalyze(url) {
  const results = {};

  results.urlPatterns = urlPatternAgent(url);
  results.domainIntel = await domainAgent(url);
  results.threatFeeds = await threatFeedAgent(url);

  // First-pass deterministic fusion from rule/intel sources.
  const deterministicScore = clampPercent(
    Math.round(
      (results.urlPatterns.patternScore * 0.28) +
      (results.domainIntel.domainRisk * 0.22) +
      (results.threatFeeds.threatScore * 0.50)
    )
  );

  const ai = await aiReasoner({
    url,
    urlPatterns: results.urlPatterns,
    domainIntel: results.domainIntel,
    threatFeeds: results.threatFeeds,
    deterministicScore
  });
  results.aiDecision = ai;

  const aiWeight = ai.available ? 0.35 : 0;
  const finalRiskScore = clampPercent(
    Math.round((deterministicScore * (1 - aiWeight)) + (Number(ai.riskScore || 0) * aiWeight))
  );
  const finalConfidence = clampPercent(
    Math.round(
      55 +
      (results.threatFeeds.sources?.virustotal?.available ? 15 : 0) +
      (results.threatFeeds.sources?.googleSafeBrowsing?.available ? 10 : 0) +
      (ai.available ? Math.min(20, Number(ai.confidence || 0) * 0.2) : 0)
    )
  );

  return {
    ...results,
    deterministicScore,
    finalRiskScore,
    riskLevel: riskLevelFromScore(finalRiskScore),
    confidence: finalConfidence,
    explanation: ai.explanation || "Multi-source analysis completed.",
    threatType: ai.threatType || "unknown",
    evidence: [
      ...(results.urlPatterns.reasons || []),
      ...(results.domainIntel.reasons || []),
      ...(results.threatFeeds.reasons || []),
      ...((ai.signals || []).map((s) => `AI: ${s}`))
    ].slice(0, 12)
  };
}

function detectPhishingPatterns(url) {
  let score = 0;

  if (url.includes("@")) score += 20;
  if (url.includes("-")) score += 10;
  if (url.includes("login")) score += 15;
  if (url.includes("verify")) score += 15;
  if (url.includes("secure")) score += 10;

  const suspiciousDomains = [
    "paypal",
    "bank",
    "amazon",
    "apple",
    "microsoft"
  ];

  suspiciousDomains.forEach((word) => {
    if (url.includes(word) && !url.includes(`${word}.com`)) {
      score += 20;
    }
  });

  return score;
}

async function checkDomainAge(domain) {
  if (!whois) return 0;
  const data = await whois(domain);

  if (data.creationDate) {
    const created = new Date(data.creationDate);
    const today = new Date();

    const ageDays = (today - created) / (1000 * 60 * 60 * 24);

    if (ageDays < 30) return 30;
  }

  return 0;
}

function getDomain(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

async function analyzeURL(url) {
  let score = 0;

  score += detectPhishingPatterns(url);

  const domain = getDomain(url);

  if (domain) {
    score += await checkDomainAge(domain);
  }

  const google = await googleCheck(url);

  if (google.matches) {
    score += 40;
  }

  if (score > 100) score = 100;

  return score;
}

function toBase64UrlNoPadding(input) {
  return Buffer.from(String(input || ""))
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function riskLevelFromScore(score) {
  if (score >= 70) return "high";
  if (score >= 40) return "medium";
  return "low";
}

async function runOpenAiUrlAssessment(urlValue, heuristic) {
  if (!openaiApiKey) {
    return {
      source: "OpenAI phishing model",
      available: false,
      matched: false,
      error: "OPENAI_API_KEY is not configured",
      riskScore: heuristic.riskScore,
      confidence: 0,
      summary: "AI source unavailable."
    };
  }

  const prompt = `
Analyze this URL for phishing and cybersecurity risk and return strict JSON only:
{
  "riskScore": number 0-100,
  "confidence": number 0-100,
  "riskLevel": "low"|"medium"|"high",
  "summary": "short summary",
  "factors": [{"name":"factor name","score":0-100}]
}
URL: ${urlValue}
Heuristic baseline risk score: ${heuristic.riskScore}
Keep factors 3 to 6 entries.
  `.trim();

  try {
    const response = await fetchWithTimeout("https://api.openai.com/v1/responses", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${openaiApiKey}`
      },
      body: JSON.stringify({
        model: openaiModel,
        input: prompt,
        temperature: 0.05
      })
    });

    if (!response.ok) {
      return {
        source: "OpenAI phishing model",
        available: false,
        matched: false,
        error: `OpenAI status ${response.status}`,
        riskScore: heuristic.riskScore,
        confidence: 0,
        summary: "AI source unavailable."
      };
    }

    const data = await response.json();
    const parsed = extractFirstJsonObject(data.output_text || "");
    if (!parsed) {
      return {
        source: "OpenAI phishing model",
        available: false,
        matched: false,
        error: "No structured JSON in model response",
        riskScore: heuristic.riskScore,
        confidence: 0,
        summary: "AI source unavailable."
      };
    }

    const normalized = normalizeRiskShape(parsed, heuristic);
    return {
      source: "OpenAI phishing model",
      available: true,
      matched: normalized.riskScore >= 55,
      error: "",
      riskScore: normalized.riskScore,
      confidence: clampPercent(Math.max(normalized.confidence, 70)),
      summary: normalized.summary || "AI phishing risk assessment completed."
    };
  } catch (err) {
    return {
      source: "OpenAI phishing model",
      available: false,
      matched: false,
      error: String(err?.message || err || "OpenAI request failed"),
      riskScore: heuristic.riskScore,
      confidence: 0,
      summary: "AI source unavailable."
    };
  }
}

async function evaluateVirusTotalUrl(urlValue) {
  const parsed = normalizeUrl(urlValue);
  if (!parsed) {
    return {
      source: "VirusTotal URL reputation",
      available: false,
      matched: false,
      error: "Invalid URL format",
      riskScore: 0,
      confidence: 0,
      summary: "VirusTotal skipped."
    };
  }

  if (!virusTotalApiKey) {
    return {
      source: "VirusTotal URL reputation",
      available: false,
      matched: false,
      error: "VIRUSTOTAL_API_KEY is not configured",
      riskScore: 0,
      confidence: 0,
      summary: "VirusTotal source unavailable."
    };
  }

  try {
    const urlId = toBase64UrlNoPadding(parsed.href);
    const response = await fetchWithTimeout(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      method: "GET",
      headers: {
        Accept: "application/json",
        "x-apikey": virusTotalApiKey
      }
    });

    if (!response.ok) {
      return {
        source: "VirusTotal URL reputation",
        available: false,
        matched: false,
        error: `VirusTotal status ${response.status}`,
        riskScore: 0,
        confidence: 0,
        summary: "VirusTotal source unavailable."
      };
    }

    const body = await response.json();
    const stats = body?.data?.attributes?.last_analysis_stats || {};
    const malicious = Number(stats.malicious || 0);
    const suspicious = Number(stats.suspicious || 0);
    const harmless = Number(stats.harmless || 0);
    const undetected = Number(stats.undetected || 0);
    const total = malicious + suspicious + harmless + undetected;
    const weightedHits = malicious + (suspicious * 0.7);
    const ratioScore = total > 0 ? (weightedHits / total) * 100 : 0;

    let riskScore = clampPercent(ratioScore + (malicious > 0 ? 25 : 0) + (suspicious > 0 ? 12 : 0));
    if (malicious >= 2 && riskScore < 80) riskScore = 80;
    if (malicious >= 5 && riskScore < 90) riskScore = 90;

    const confidence = clampPercent(total > 0 ? Math.min(95, 45 + (total * 2)) : 35);
    const matched = malicious > 0 || suspicious > 0;
    const summary = matched
      ? `VirusTotal flagged this URL (malicious: ${malicious}, suspicious: ${suspicious}).`
      : "VirusTotal did not flag this URL in its latest analysis.";

    return {
      source: "VirusTotal URL reputation",
      available: true,
      matched,
      error: "",
      riskScore,
      confidence,
      summary
    };
  } catch (err) {
    return {
      source: "VirusTotal URL reputation",
      available: false,
      matched: false,
      error: String(err?.message || err || "VirusTotal request failed"),
      riskScore: 0,
      confidence: 0,
      summary: "VirusTotal source unavailable."
    };
  }
}

async function evaluateGoogleSafeBrowsing(urlValue) {
  const parsed = normalizeUrl(urlValue);
  if (!parsed) {
    return {
      source: "Google Safe Browsing",
      available: false,
      matched: false,
      error: "Invalid URL format",
      riskScore: 0,
      confidence: 0,
      summary: "Safe Browsing skipped."
    };
  }

  if (!googleSafeBrowsingApiKey) {
    return {
      source: "Google Safe Browsing",
      available: false,
      matched: false,
      error: "GOOGLE_SAFE_BROWSING_API_KEY is not configured",
      riskScore: 0,
      confidence: 0,
      summary: "Safe Browsing source unavailable."
    };
  }

  try {
    const endpoint = `${googleSafeBrowsingApiUrl}?key=${encodeURIComponent(googleSafeBrowsingApiKey)}`;
    const response = await fetchWithTimeout(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        client: {
          clientId: "cyber-shield",
          clientVersion: "1.0.0"
        },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url: parsed.href }]
        }
      })
    });

    if (!response.ok) {
      return {
        source: "Google Safe Browsing",
        available: false,
        matched: false,
        error: `Google Safe Browsing status ${response.status}`,
        riskScore: 0,
        confidence: 0,
        summary: "Safe Browsing source unavailable."
      };
    }

    const body = await response.json();
    const matches = Array.isArray(body?.matches) ? body.matches : [];
    if (matches.length === 0) {
      return {
        source: "Google Safe Browsing",
        available: true,
        matched: false,
        error: "",
        riskScore: 8,
        confidence: 80,
        summary: "Google Safe Browsing found no threat match for this URL."
      };
    }

    const threatTypes = matches.map((m) => String(m.threatType || "")).filter(Boolean);
    const hasSocial = threatTypes.includes("SOCIAL_ENGINEERING");
    const hasMalware = threatTypes.includes("MALWARE");
    let riskScore = 88;
    if (hasSocial || hasMalware) riskScore = 95;

    return {
      source: "Google Safe Browsing",
      available: true,
      matched: true,
      error: "",
      riskScore,
      confidence: 94,
      summary: `Google Safe Browsing matched threat types: ${threatTypes.join(", ")}.`
    };
  } catch (err) {
    return {
      source: "Google Safe Browsing",
      available: false,
      matched: false,
      error: String(err?.message || err || "Google Safe Browsing request failed"),
      riskScore: 0,
      confidence: 0,
      summary: "Safe Browsing source unavailable."
    };
  }
}

function buildGithubUrlSource(intel) {
  if (intel?.error) {
    return {
      source: "GitHub phishing feed",
      available: false,
      matched: false,
      error: intel.error,
      riskScore: 0,
      confidence: 0,
      summary: "GitHub feed unavailable."
    };
  }

  if (intel?.matched) {
    const exact = intel.matchType === "exact-url";
    return {
      source: "GitHub phishing feed",
      available: true,
      matched: true,
      error: "",
      riskScore: exact ? 96 : 90,
      confidence: 90,
      summary: exact
        ? "GitHub feed exact URL match."
        : `GitHub feed domain match: ${intel.indicator}.`
    };
  }

  return {
    source: "GitHub phishing feed",
    available: true,
    matched: false,
    error: "",
    riskScore: 12,
    confidence: 70,
    summary: "No GitHub phishing feed match."
  };
}

function aggregateUrlRisk(assessments) {
  const weighted = assessments.filter((item) => item.available && item.weight > 0);
  const totalWeight = weighted.reduce((sum, item) => sum + item.weight, 0) || 1;
  let riskScore = clampPercent(weighted.reduce((sum, item) => sum + (item.riskScore * item.weight), 0) / totalWeight);
  const confidence = clampPercent(weighted.reduce((sum, item) => sum + (item.confidence * item.weight), 0) / totalWeight);

  const activeThreatMatches = weighted.filter((item) => item.matched && item.key !== "heuristic");
  const strongMatch = activeThreatMatches.some((item) => item.riskScore >= 90);
  if (strongMatch && riskScore < 80) riskScore = 80;
  if (activeThreatMatches.length >= 2 && riskScore < 72) riskScore = 72;
  if (weighted.some((item) => item.key === "gsb" && item.matched) && riskScore < 85) riskScore = 85;

  const riskLevel = riskLevelFromScore(riskScore);
  const factors = weighted
    .map((item) => ({ name: item.source, score: clampPercent(item.riskScore) }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 6);

  const matchedSourceNames = activeThreatMatches.map((item) => item.source);
  const summary = matchedSourceNames.length
    ? `High-risk detections from ${matchedSourceNames.join(", ")}. Combined multi-source risk scoring applied.`
    : "No direct threat feed hit detected; combined heuristic and AI signals were used for risk scoring.";

  return {
    riskScore,
    confidence,
    riskLevel,
    summary: summary.slice(0, 280),
    factors
  };
}

function randomPick(list) {
  return list[Math.floor(Math.random() * list.length)];
}

function shuffle(list) {
  const arr = [...list];
  for (let i = arr.length - 1; i > 0; i -= 1) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

function createQuestionId() {
  return crypto.randomUUID ? crypto.randomUUID() : `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
}

function prunePhishingQuestions() {
  const now = Date.now();
  for (const [id, q] of phishingQuestions.entries()) {
    if (!q || (now - q.createdAt) > PHISHING_TTL_MS) {
      phishingQuestions.delete(id);
    }
  }
}

function prunePhishingTimelineRuns() {
  const now = Date.now();
  for (const [id, run] of phishingTimelineRuns.entries()) {
    if (!run || (now - run.createdAt) > PHISHING_TTL_MS) {
      phishingTimelineRuns.delete(id);
    }
  }
}

function prunePasswordQuestions() {
  const now = Date.now();
  for (const [id, q] of passwordQuestions.entries()) {
    if (!q || (now - q.createdAt) > PHISHING_TTL_MS) {
      passwordQuestions.delete(id);
    }
  }
}

function pruneSafeLinkQuestions() {
  const now = Date.now();
  for (const [id, q] of safeLinkQuestions.entries()) {
    if (!q || (now - q.createdAt) > PHISHING_TTL_MS) {
      safeLinkQuestions.delete(id);
    }
  }
}

function pruneMalwareQuestions() {
  const now = Date.now();
  for (const [id, q] of malwareQuestions.entries()) {
    if (!q || (now - q.createdAt) > PHISHING_TTL_MS) {
      malwareQuestions.delete(id);
    }
  }
}

function pruneMalwareChainRuns() {
  const now = Date.now();
  for (const [id, run] of malwareChainRuns.entries()) {
    if (!run || (now - run.createdAt) > PHISHING_TTL_MS) {
      malwareChainRuns.delete(id);
    }
  }
}

function generateStrongPassword() {
  const words = ["Falcon", "Shield", "Orbit", "Cipher", "Vector", "Atlas"];
  const symbols = ["!", "@", "#", "$", "%", "&"];
  return `${randomPick(words)}${Math.floor(100 + Math.random() * 900)}${randomPick(symbols)}${randomPick(words).toLowerCase()}`;
}

function generateWeakPassword() {
  const weak = ["password123", "qwerty123", "admin2024", "iloveyou1", "welcome123", "12345678"];
  return randomPick(weak);
}

function buildFallbackPasswordQuestion() {
  const strong = Math.random() < 0.45;
  const password = strong ? generateStrongPassword() : generateWeakPassword();
  const context = randomPick([
    "You need a password for your banking app.",
    "Create a password for your primary email account.",
    "Set a password for cloud storage containing personal files.",
    "Create a password for your work account."
  ]);

  const options = [
    { id: "use_now", text: "Use this password as it is" },
    { id: "improve", text: "Make this password stronger before using it" },
    { id: "reuse_old", text: "Reuse your old password from another account" },
    { id: "share", text: "Share this password with a friend for backup" }
  ];

  return {
    question: "What is the safest decision for this password?",
    context,
    password,
    options: shuffle(options),
    correctOption: strong ? "use_now" : "improve",
    explanation: strong
      ? "This password has good length and mixed character types, so it is safer to use."
      : "This password is easy to guess or commonly used. Improve it with length, symbols, and uniqueness.",
    difficulty: "beginner"
  };
}

async function buildLlmPasswordQuestion() {
  const seed = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const prompt = `
You are creating a beginner password-security game challenge.
Return strict JSON only:
{
  "question": "string",
  "context": "string",
  "password": "string",
  "options": [
    {"id":"use_now","text":"..."},
    {"id":"improve","text":"..."},
    {"id":"reuse_old","text":"..."},
    {"id":"share","text":"..."}
  ],
  "correctOption": "use_now|improve|reuse_old|share",
  "explanation": "short explanation",
  "difficulty": "beginner"
}
Rules:
- Use simple English.
- Exactly one best answer.
- Scenario must vary each time.
- Seed: ${seed}
  `.trim();

  const fallback = buildFallbackPasswordQuestion();
  if (!openaiApiKey) return fallback;

  let parsed = null;
  try {
    const response = await fetch("https://api.openai.com/v1/responses", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${openaiApiKey}`
      },
      body: JSON.stringify({
        model: openaiModel,
        input: prompt,
        temperature: 0.35
      })
    });
    if (response.ok) {
      const data = await response.json();
      parsed = extractFirstJsonObject(data.output_text || "");
    }
  } catch {
    parsed = null;
  }

  if (!parsed) return fallback;

  const optionMap = new Map((Array.isArray(parsed.options) ? parsed.options : []).map((o) => [String(o.id || ""), String(o.text || "")]));
  const options = shuffle([
    { id: "use_now", text: optionMap.get("use_now") || "Use this password as it is" },
    { id: "improve", text: optionMap.get("improve") || "Make this password stronger before using it" },
    { id: "reuse_old", text: optionMap.get("reuse_old") || "Reuse your old password from another account" },
    { id: "share", text: optionMap.get("share") || "Share this password with a friend for backup" }
  ]);
  const correctOption = String(parsed.correctOption || "").toLowerCase();
  const safeCorrect = ["use_now", "improve", "reuse_old", "share"].includes(correctOption) ? correctOption : fallback.correctOption;

  return {
    question: String(parsed.question || fallback.question).slice(0, 220),
    context: String(parsed.context || fallback.context).slice(0, 220),
    password: String(parsed.password || fallback.password).slice(0, 120),
    options,
    correctOption: safeCorrect,
    explanation: String(parsed.explanation || fallback.explanation).slice(0, 260),
    difficulty: "beginner"
  };
}

function buildFallbackPhishingQuestion() {
  const brands = ["Microsoft 365", "PayPal", "Google Workspace", "Bank Security", "DocuSign", "AWS Billing"];
  const intents = [
    "unusual sign-in attempt",
    "invoice overdue warning",
    "mailbox quota exceeded",
    "document signature pending",
    "payment failure alert",
    "password expires today"
  ];
  const suspiciousDomains = [
    "microsoft-secure-login.click",
    "secure-docusign-verify.work",
    "paypa1-alerts.zip",
    "google-auth-reset.cam",
    "aws-billing-update.gq"
  ];
  const safeDomains = [
    "microsoft.com",
    "google.com",
    "docusign.com",
    "paypal.com",
    "amazonaws.com"
  ];
  const cta = ["verify now", "confirm account", "reset password", "review bill", "open document"];
  const urgency = ["within 30 minutes", "today", "immediately", "before account suspension"];

  const brand = randomPick(brands);
  const intent = randomPick(intents);
  const badDomain = randomPick(suspiciousDomains);
  const safeDomain = randomPick(safeDomains);
  const action = randomPick(cta);
  const due = randomPick(urgency);

  const isPhish = Math.random() < 0.72;
  const from = isPhish
    ? `${brand} Security <notice@${badDomain}>`
    : `${brand} Security <security@${safeDomain}>`;
  const subject = `${brand}: ${intent}`;
  const link = isPhish ? `https://${badDomain}/${action.replace(/\s+/g, "-")}` : `https://${safeDomain}/${action.replace(/\s+/g, "-")}`;
  const snippet = isPhish
    ? `There is a problem with your account. Please ${action} ${due} or your account may be locked.`
    : `This is a normal security message. Open the official app/site to check activity.`;

  const correctOption = isPhish ? "report" : "review";
  const options = shuffle([
    { id: "report", text: "Mark as phishing and do not click the link" },
    { id: "review", text: "Open the official website/app yourself and check there" },
    { id: "reply", text: "Reply with your password or OTP" },
    { id: "download", text: "Download the file from email and run it" }
  ]);

  const explanation = isPhish
    ? `This is likely phishing. The sender/link (${badDomain}) looks suspicious and the email uses urgency to pressure you.`
    : "This looks safer, but still use the official website/app directly instead of trusting email links.";

  return {
    question: "What should you do with this email?",
    emailPreview: { from, subject, snippet, link },
    options,
    correctOption,
    explanation,
    riskLabel: isPhish ? "Likely Phishing" : "Likely Legitimate"
  };
}

async function buildLlmPhishingQuestion() {
  const scenarioSeed = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const prompt = `
You are generating a phishing-awareness game question.
Create ONE unique scenario (different from common textbook examples) and return strict JSON only:
{
  "question": "string",
  "emailPreview": {
    "from": "string",
    "subject": "string",
    "snippet": "string",
    "link": "string"
  },
  "options": [
    {"id":"report","text":"..."},
    {"id":"review","text":"..."},
    {"id":"reply","text":"..."},
    {"id":"download","text":"..."}
  ],
  "correctOption": "report|review|reply|download",
  "explanation": "short explanation",
  "riskLabel": "Likely Phishing|Likely Legitimate"
}
Rules:
- Use simple English (easy for beginners, age 13+).
- Keep options realistic and safety-focused.
- Ensure exactly one best answer.
- Include subtle clues, not only obvious ones.
- Scenario seed: ${scenarioSeed}
  `.trim();

  const fallback = buildFallbackPhishingQuestion();
  if (!openaiApiKey) return fallback;

  let parsed = null;
  try {
    const response = await fetch("https://api.openai.com/v1/responses", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${openaiApiKey}`
      },
      body: JSON.stringify({
        model: openaiModel,
        input: prompt,
        temperature: 0.4
      })
    });
    if (response.ok) {
      const data = await response.json();
      parsed = extractFirstJsonObject(data.output_text || "");
    }
  } catch {
    parsed = null;
  }

  if (!parsed) return fallback;

  const optionsRaw = Array.isArray(parsed.options) ? parsed.options : [];
  const optionMap = new Map(optionsRaw.map((o) => [String(o.id || ""), String(o.text || "")]));
  const options = shuffle([
    { id: "report", text: optionMap.get("report") || "Mark as phishing and do not click the link" },
    { id: "review", text: optionMap.get("review") || "Open the official website/app yourself and check there" },
    { id: "reply", text: optionMap.get("reply") || "Reply with your password or OTP" },
    { id: "download", text: optionMap.get("download") || "Download the file from email and run it" }
  ]);
  const correctOption = String(parsed.correctOption || "").toLowerCase();
  const safeCorrect = ["report", "review", "reply", "download"].includes(correctOption) ? correctOption : fallback.correctOption;

  return {
    question: String(parsed.question || fallback.question).slice(0, 240),
    emailPreview: {
      from: String(parsed.emailPreview?.from || fallback.emailPreview.from).slice(0, 160),
      subject: String(parsed.emailPreview?.subject || fallback.emailPreview.subject).slice(0, 180),
      snippet: String(parsed.emailPreview?.snippet || fallback.emailPreview.snippet).slice(0, 320),
      link: String(parsed.emailPreview?.link || fallback.emailPreview.link).slice(0, 220)
    },
    options,
    correctOption: safeCorrect,
    explanation: String(parsed.explanation || fallback.explanation).slice(0, 260),
    riskLabel: String(parsed.riskLabel || fallback.riskLabel).slice(0, 32)
  };
}

function buildTimelinePhishingEmail(type) {
  const suspiciousDomains = [
    "account-security-check.click",
    "verify-now-login.work",
    "secure-alert-center.cam",
    "team-message-update.zip"
  ];
  const trustedDomains = [
    "microsoft.com",
    "google.com",
    "docusign.com",
    "amazonaws.com"
  ];
  const departments = ["HR", "Finance", "IT Support", "Security Team", "Project Ops"];
  const actions = ["review account activity", "confirm a notification", "check a shared document", "verify a request"];

  if (type === "report") {
    const fakeDomain = randomPick(suspiciousDomains);
    const subject = randomPick([
      "Urgent: Account suspension warning",
      "Action required: Security lock in 30 minutes",
      "Final notice: Verify now to avoid access loss"
    ]);
    const snippet = randomPick([
      "You must confirm password and OTP immediately.",
      "Failure to verify now may disable your account.",
      "Complete verification in 20 minutes to avoid lock."
    ]);
    return {
      id: createQuestionId(),
      emailPreview: {
        from: `Security Alert <notice@${fakeDomain}>`,
        subject,
        snippet,
        link: `https://${fakeDomain}/verify-now`
      },
      triage: "report",
      explanation: "Urgency, suspicious domain, and credential pressure indicate phishing."
    };
  }

  if (type === "safe") {
    const trusted = randomPick(trustedDomains);
    const dept = randomPick(departments);
    const action = randomPick(actions);
    return {
      id: createQuestionId(),
      emailPreview: {
        from: `${dept} <noreply@${trusted}>`,
        subject: `Routine notice: ${action}`,
        snippet: "No password or OTP is requested. You can verify from the official app.",
        link: `https://${trusted}/security`
      },
      triage: "safe",
      explanation: "Looks routine and non-coercive. Still verify via official channel."
    };
  }

  const trusted = randomPick(trustedDomains);
  const dept = randomPick(departments);
  const snippet = randomPick([
    "Unexpected request arrived from a new vendor contact.",
    "The message asks for quick acknowledgement before EOD.",
    "Sender context is incomplete; details are limited."
  ]);
  return {
    id: createQuestionId(),
    emailPreview: {
      from: `${dept} <updates@${trusted}>`,
      subject: "Please review this unusual request",
      snippet,
      link: `https://${trusted}/shared/review`
    },
    triage: "suspicious",
    explanation: "No direct phishing proof, but context is unusual and needs manual verification."
  };
}

function buildPhishingTimelineRound() {
  const types = shuffle(["report", "safe", "suspicious", "report", "safe", "suspicious"]);
  return types.map((type) => buildTimelinePhishingEmail(type));
}

function baseUrlHeuristic(urlValue) {
  const parsed = normalizeUrl(urlValue);
  if (!parsed) {
    return {
      riskScore: 95,
      confidence: 85,
      riskLevel: "high",
      summary: "URL format is invalid or malformed, which is often a strong phishing indicator.",
      factors: [
        { name: "URL structure", score: 95 },
        { name: "Destination trust", score: 90 },
        { name: "Technical signals", score: 88 }
      ]
    };
  }

  const host = parsed.hostname.toLowerCase();
  const pathText = `${parsed.pathname}${parsed.search}`.toLowerCase();
  const isHttps = parsed.protocol === "https:";
  const hostParts = host.split(".");
  const subdomainCount = Math.max(0, hostParts.length - 2);
  const hasIpHost = /^[0-9.]+$/.test(host);
  const hasAtSymbol = parsed.href.includes("@");
  const suspiciousWords = ["login", "verify", "secure", "update", "password", "wallet", "banking", "confirm", "account", "signin", "auth"];
  const pathSuspiciousHits = suspiciousWords.filter((word) => pathText.includes(word)).length;
  const hostSuspiciousHits = suspiciousWords.filter((word) => host.includes(word)).length;
  const brandSensitiveWords = ["bank", "paypal", "apple", "microsoft", "gmail", "telegram", "whatsapp", "amazon"];
  const hostBrandHits = brandSensitiveWords.filter((word) => host.includes(word)).length;
  const hostCredentialCombo = ["bank", "login", "verify", "update", "secure"].filter((word) => host.includes(word)).length;
  const lureWords = ["coin", "coins", "generator", "unlimited", "free", "bonus", "gift", "claim", "airdrop", "hack", "crack", "mod", "cheat", "loot"];
  const hostLureHits = lureWords.filter((word) => host.includes(word)).length;
  const hasComPrefixTrap = /^com\./i.test(host);
  const tld = hostParts[hostParts.length - 1] || "";
  const hasRareTld = tld.length >= 7;
  const generatorScamPattern = host.includes("generator") && /(coin|coins|free|bonus|unlimited)/i.test(host);
  const hasPunycode = host.includes("xn--");
  const hasLongUrl = parsed.href.length > 120;
  const hasManyHyphens = (host.match(/-/g) || []).length >= 2;
  const hasEncodedChars = /%[0-9a-f]{2}/i.test(parsed.href);
  const hasSuspiciousTld = /\.(zip|mov|click|cam|work|country|gq|tk|ml)$/i.test(host);
  const hasUserInfo = !!parsed.username;
  const nonStandardPort = parsed.port && !["80", "443"].includes(parsed.port);

  const domainRisk = clampPercent(
    (hasIpHost ? 40 : 0) +
    (hasPunycode ? 25 : 0) +
    (subdomainCount >= 3 ? 20 : subdomainCount * 6) +
    (hasManyHyphens ? 10 : 0) +
    (hasSuspiciousTld ? 20 : 0) +
    (hostLureHits * 14) +
    (hasComPrefixTrap ? 18 : 0) +
    (hasRareTld ? 10 : 0)
  );
  const pathRisk = clampPercent(
    (pathSuspiciousHits * 12) +
    (hostSuspiciousHits * 14) +
    (hostBrandHits * 10) +
    (hasLongUrl ? 12 : 0) +
    (hasAtSymbol ? 20 : 0) +
    (hasEncodedChars ? 12 : 0)
  );
  const technicalRisk = clampPercent(
    (isHttps ? 10 : 45) +
    (parsed.port ? 8 : 0) +
    (hasUserInfo ? 18 : 0) +
    (nonStandardPort ? 14 : 0)
  );
  let riskScore = clampPercent((domainRisk * 0.42) + (pathRisk * 0.33) + (technicalRisk * 0.25));
  if (hostSuspiciousHits >= 2 && riskScore < 62) riskScore = 62;
  if (hostSuspiciousHits >= 3 && riskScore < 74) riskScore = 74;
  if (hostBrandHits >= 1 && hostSuspiciousHits >= 2 && riskScore < 78) riskScore = 78;
  if (hostCredentialCombo >= 3 && riskScore < 86) riskScore = 86;
  if (!isHttps && hostCredentialCombo >= 2 && riskScore < 90) riskScore = 90;
  if (!isHttps && hasManyHyphens && hostSuspiciousHits >= 2 && riskScore < 88) riskScore = 88;
  if (hostLureHits >= 2 && riskScore < 72) riskScore = 72;
  if (hostLureHits >= 3 && riskScore < 82) riskScore = 82;
  if (generatorScamPattern && riskScore < 90) riskScore = 90;
  const riskLevel = riskScore >= 70 ? "high" : riskScore >= 40 ? "medium" : "low";

  return {
    riskScore,
    confidence: 74,
    riskLevel,
    summary: "Heuristic risk estimate based on URL structure, destination pattern, and suspicious token signals.",
    factors: [
      { name: "Domain reputation signal", score: domainRisk },
      { name: "Path and keyword signal", score: pathRisk },
      { name: "Technical/security signal", score: technicalRisk }
    ]
  };
}

function baseApkHeuristic(apkValue, sourceValue) {
  const apk = String(apkValue || "").trim();
  const source = String(sourceValue || "Unknown").trim();
  const isSha256 = /^[a-f0-9]{64}$/i.test(apk);
  const isPackage = /^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,}$/i.test(apk);
  const hasSuspiciousWords = /(mod|crack|hacked|pro|premium|unlock|cheat|free|inject|spy)/i.test(apk);
  const hasExecutableMasquerade = /\.(exe|scr|bat|js)$/i.test(apk);
  const hasOddChars = /[^a-z0-9._-]/i.test(apk);
  const longToken = apk.length > 120;
  const looksLikeBrandImpersonation = /(whatsap|faceb0ok|insta|telegram|paytm|gpay|amazon|netflix)/i.test(apk);
  const tooManyNumericSegments = (apk.match(/\d+/g) || []).length >= 3;

  const sourceRiskMap = {
    "Play Store": 18,
    "Direct Download": 58,
    Unknown: 72
  };
  const sourceRisk = sourceRiskMap[source] ?? 72;

  const identityRisk = clampPercent(
    (isSha256 ? 20 : 0) +
    (isPackage ? 28 : 45) +
    (hasOddChars ? 22 : 0) +
    (longToken ? 12 : 0)
  );
  const behaviorRisk = clampPercent(
    (hasSuspiciousWords ? 55 : 18) +
    (hasExecutableMasquerade ? 20 : 0) +
    (looksLikeBrandImpersonation ? 18 : 0) +
    (tooManyNumericSegments ? 10 : 0)
  );
  const overall = clampPercent((sourceRisk * 0.35) + (identityRisk * 0.30) + (behaviorRisk * 0.35));
  const riskLevel = overall >= 70 ? "high" : overall >= 40 ? "medium" : "low";

  let summary = "APK risk estimated from source trust, naming integrity, and suspicious behavioral indicators.";
  if (isSha256) {
    summary = "Hash-based submission detected; risk estimated from source trust and suspicious string indicators.";
  }

  return {
    riskScore: overall,
    confidence: 72,
    riskLevel,
    summary,
    factors: [
      { name: "Source trust", score: sourceRisk },
      { name: "Identity integrity", score: identityRisk },
      { name: "Behavioral indicators", score: behaviorRisk }
    ]
  };
}

function extractPackageFromApkUrl(rawValue) {
  const value = String(rawValue || "").trim();
  if (!/^https?:\/\//i.test(value)) return "";

  try {
    const parsed = new URL(value);
    const packagePattern = /^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,}$/i;
    const queryKeys = ["id", "package", "pkg", "appid", "bundleid"];

    for (const key of queryKeys) {
      const queryValue = String(parsed.searchParams.get(key) || "").trim();
      if (packagePattern.test(queryValue)) return queryValue;
    }

    const segments = parsed.pathname
      .split("/")
      .map((part) => {
        try {
          return decodeURIComponent(part).trim();
        } catch {
          return String(part || "").trim();
        }
      })
      .filter(Boolean)
      .reverse();

    for (const segment of segments) {
      if (packagePattern.test(segment)) return segment;
    }
  } catch {
    return "";
  }

  return "";
}

function normalizeApkInput(apkValue) {
  const apk = String(apkValue || "").trim();
  if (!apk) return "";

  const packagePattern = /^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,}$/i;
  const isSha256 = /^[a-f0-9]{64}$/i.test(apk);
  const isPackage = packagePattern.test(apk);
  const isApkFileName = /^[a-z0-9._ -]+\.apk$/i.test(apk) && !/[\\/]/.test(apk);
  const isApkPath = /(?:^|[\\/])[^\\/]+\.apk$/i.test(apk);

  if (isSha256 || isPackage || isApkFileName || isApkPath) {
    return apk;
  }

  const extractedPackage = extractPackageFromApkUrl(apk);
  return extractedPackage || apk;
}

function isValidApkInput(apkValue) {
  const apk = normalizeApkInput(apkValue);
  if (!apk) return false;
  const isSha256 = /^[a-f0-9]{64}$/i.test(apk);
  const isPackage = /^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,}$/i.test(apk);
  const isApkFileName = /^[a-z0-9._ -]+\.apk$/i.test(apk) && !/[\\/]/.test(apk);
  const isApkPath = /(?:^|[\\/])[^\\/]+\.apk$/i.test(apk);
  return isSha256 || isPackage || isApkFileName || isApkPath;
}

async function llmApkAnalysis(apkValue, sourceValue, heuristic) {
  const prompt = `
You are an Android malware triage security agent.
Perform a structured APK risk assessment using the provided APK package/hash text and source.
Return strict JSON only:
{
  "riskScore": number 0-100,
  "confidence": number 0-100,
  "riskLevel": "low"|"medium"|"high",
  "summary": "short summary",
  "factors": [{"name":"factor name","score":0-100}]
}
APK_INPUT: ${apkValue}
SOURCE: ${sourceValue}
HEURISTIC_BASELINE_SCORE: ${heuristic.riskScore}
Include 3 to 6 factors and keep analysis conservative.
  `.trim();

  const llm = await callLlmRiskAssessment(prompt, heuristic);
  return blendRisk(llm, heuristic, 0.66);
}

function baseEmailHeuristic(emailTextValue) {
  const text = String(emailTextValue || "").trim();
  const lower = text.toLowerCase();

  const hasFrom = /^from:/im.test(text);
  const hasReplyTo = /^reply-to:/im.test(text);
  const hasSpfFail = /(spf=fail|spf:\s*fail|received-spf:\s*fail)/i.test(text);
  const hasDkimFail = /(dkim=fail|dkim:\s*fail)/i.test(text);
  const hasDmarcFail = /(dmarc=fail|dmarc:\s*fail)/i.test(text);
  const urgentWords = [
    "urgent", "immediately", "verify", "suspended", "reset", "login", "payment",
    "invoice", "gift card", "act now", "final warning", "limited time", "confirm now"
  ];
  const urgentHits = urgentWords.filter((word) => lower.includes(word)).length;
  const linkMatches = text.match(/https?:\/\/[^\s)>"']+/gi) || [];
  const fromHeader = (text.match(/^from:\s*(.+)$/im) || [])[1] || "";
  const replyHeader = (text.match(/^reply-to:\s*(.+)$/im) || [])[1] || "";
  const fromDomain = (fromHeader.match(/@([a-z0-9.-]+\.[a-z]{2,})/i) || [])[1] || "";
  const replyDomain = (replyHeader.match(/@([a-z0-9.-]+\.[a-z]{2,})/i) || [])[1] || "";
  const domainMismatch = !!(fromDomain && replyDomain && fromDomain.toLowerCase() !== replyDomain.toLowerCase());
  const shortenerPattern = /(bit\.ly|tinyurl\.com|t\.co|cutt\.ly|shorturl\.at)/i;
  const shortenedCount = linkMatches.filter((u) => shortenerPattern.test(u)).length;
  const mismatchHint = /(display name|spoof|lookalike|impersonat)/i.test(lower);
  const attachmentHint = /(attachment|\.zip|\.exe|\.js|\.scr|macro|enable content|html attachment|password protected)/i.test(lower);
  const credentialHarvestHint = /(password|otp|one[- ]time|verification code|bank|wallet|kyc|account locked|unusual activity)/i.test(lower);
  const moneyPressureHint = /(wire transfer|crypto|bitcoin|usdt|gift card|pay now|overdue|penalty)/i.test(lower);
  const threatWords = /(lawsuit|legal action|terminate|deactivate|breach|compromised)/i.test(lower);
  const suspiciousTldPattern = /\.(zip|mov|click|cam|work|country|gq|tk|ml)(\/|$)/i;
  const suspiciousTldCount = linkMatches.filter((u) => suspiciousTldPattern.test(u)).length;
  const atSymbolLinkCount = linkMatches.filter((u) => /@/.test(u)).length;
  const htmlBody = /<html|<body|<a\s+href=/i.test(text);
  const manyExclamations = (text.match(/!/g) || []).length >= 3;
  const allCapsWords = (text.match(/\b[A-Z]{4,}\b/g) || []).length;
  const highCapsPressure = allCapsWords >= 4;

  const authRisk = clampPercent(
    (hasSpfFail ? 40 : 0) +
    (hasDkimFail ? 30 : 0) +
    (hasDmarcFail ? 25 : 0) +
    (!hasFrom ? 12 : 0) +
    (hasReplyTo ? 10 : 0) +
    (domainMismatch ? 20 : 0)
  );
  const socialRisk = clampPercent(
    (urgentHits * 11) +
    (mismatchHint ? 16 : 0) +
    (credentialHarvestHint ? 20 : 0) +
    (moneyPressureHint ? 20 : 0) +
    (threatWords ? 16 : 0) +
    (manyExclamations ? 10 : 0) +
    (highCapsPressure ? 12 : 0)
  );
  const linkRisk = clampPercent(
    (linkMatches.length * 10) +
    (shortenedCount * 18) +
    (attachmentHint ? 20 : 0) +
    (domainMismatch ? 16 : 0) +
    (suspiciousTldCount * 20) +
    (atSymbolLinkCount * 16) +
    (htmlBody ? 8 : 0)
  );
  let overall = clampPercent((authRisk * 0.38) + (socialRisk * 0.34) + (linkRisk * 0.28));

  // Hard calibration so obvious phishing/spam cannot remain in low-risk zone.
  const redFlags = [
    hasSpfFail || hasDkimFail || hasDmarcFail,
    domainMismatch,
    shortenedCount > 0 || suspiciousTldCount > 0 || atSymbolLinkCount > 0,
    credentialHarvestHint || moneyPressureHint || threatWords,
    attachmentHint
  ].filter(Boolean).length;

  if (redFlags >= 2 && overall < 55) overall = 55;
  if (redFlags >= 3 && overall < 70) overall = 70;
  if (redFlags >= 4 && overall < 82) overall = 82;

  const riskLevel = overall >= 70 ? "high" : overall >= 40 ? "medium" : "low";

  return {
    riskScore: overall,
    confidence: clampPercent(72 + (redFlags * 5)),
    riskLevel,
    summary: "Email risk estimated from authentication indicators, social engineering signals, and suspicious links/attachments.",
    factors: [
      { name: "Authentication checks", score: authRisk },
      { name: "Social engineering language", score: socialRisk },
      { name: "Link/attachment indicators", score: linkRisk }
    ]
  };
}

async function llmEmailAnalysis(emailTextValue, heuristic) {
  const prompt = `
You are a phishing and email-security triage agent.
Analyze this email text (headers/body) for malicious risk.
Return strict JSON only:
{
  "riskScore": number 0-100,
  "confidence": number 0-100,
  "riskLevel": "low"|"medium"|"high",
  "summary": "short summary",
  "factors": [{"name":"factor name","score":0-100}]
}
EMAIL_TEXT:
${emailTextValue.slice(0, 5000)}
HEURISTIC_BASELINE_SCORE: ${heuristic.riskScore}
Important calibration rules:
- If credential theft/payment pressure/social engineering is clear, avoid low risk.
- If authentication failures (SPF/DKIM/DMARC) or domain mismatch are present, risk should usually be medium/high.
- Do not under-score obvious spam or phishing phrasing.
Use 3 to 6 factors.
  `.trim();

  const llm = await callLlmRiskAssessment(prompt, heuristic);
  const blended = blendRisk(llm, heuristic, 0.58);
  // Guard rail: when heuristic is clearly high-risk, do not let model drag it too low.
  if (heuristic.riskScore >= 75 && blended.riskScore < 70) {
    blended.riskScore = 70;
    blended.riskLevel = "high";
  } else if (heuristic.riskScore >= 55 && blended.riskScore < 50) {
    blended.riskScore = 50;
    blended.riskLevel = "medium";
  }
  return blended;
}

function buildSafeLinkOptions() {
  return shuffle([
    { id: "avoid", text: "Do not open this link. Use the official app/site manually." },
    { id: "inspect", text: "Verify domain and path carefully, then open only if it exactly matches the official source." },
    { id: "click_now", text: "Open the link immediately so you do not miss the deadline." },
    { id: "share", text: "Share this link with others and ask them to test it first." }
  ]);
}

function evaluateSafeLink(urlValue) {
  const parsed = normalizeUrl(urlValue);
  if (!parsed) {
    return {
      riskScore: 95,
      riskLevel: "high",
      correctOption: "avoid",
      explanation: "This URL is malformed or invalid. Treat it as unsafe and use an official source manually."
    };
  }

  const heuristic = baseUrlHeuristic(parsed.href);
  const host = parsed.hostname.toLowerCase();
  const trustedRoots = ["google.com", "microsoft.com", "apple.com", "adobe.com", "amazon.com", "paypal.com", "bankofamerica.com"];
  const trustedDomain = trustedRoots.some((root) => host === root || host.endsWith(`.${root}`));
  const isHttps = parsed.protocol === "https:";

  let riskScore = Number(heuristic.riskScore || 0);
  if (trustedDomain && isHttps && riskScore < 55) {
    riskScore = Math.max(8, riskScore - 18);
  }
  if (!isHttps) {
    riskScore = Math.max(riskScore, 55);
  }
  riskScore = clampPercent(riskScore);

  const riskLevel = riskScore >= 70 ? "high" : riskScore >= 40 ? "medium" : "low";
  const correctOption = riskScore >= 45 ? "avoid" : "inspect";
  const explanation = correctOption === "avoid"
    ? `Risk is ${riskScore}% (${riskLevel}). This link has suspicious structure/signals, so avoid opening it and verify via official channels.`
    : `Risk is ${riskScore}% (${riskLevel}). No strong red flags found, but still verify the exact domain/path before opening.`;

  return { riskScore, riskLevel, correctOption, explanation };
}

function buildFallbackSafeLinkQuestion() {
  const suspiciousUrls = [
    "https://secure-paypa1-alerts.click/verify-now",
    "http://update-account-security.work/login",
    "https://microsoft-reset-support.gq/restore",
    "https://accounts-google-security.cam/session-check",
    "https://amazon-billing-review.zip/invoice"
  ];
  const saferUrls = [
    "https://accounts.google.com/signin/v2/challenge",
    "https://www.adobe.com/account/security",
    "https://www.microsoft.com/security",
    "https://www.apple.com/privacy/",
    "https://www.paypal.com/signin"
  ];
  const contexts = [
    "You received this link in a message saying your account needs urgent action.",
    "A coworker forwarded this link and asked if it is safe.",
    "This link appeared in a social media direct message.",
    "You found this link in an email about account verification."
  ];

  const risky = Math.random() < 0.72;
  const url = risky ? randomPick(suspiciousUrls) : randomPick(saferUrls);
  const evaluated = evaluateSafeLink(url);

  return {
    question: "What is the safest action for this link?",
    context: randomPick(contexts),
    url,
    options: buildSafeLinkOptions(),
    correctOption: evaluated.correctOption,
    explanation: evaluated.explanation,
    riskScore: evaluated.riskScore,
    riskLevel: evaluated.riskLevel,
    difficulty: "beginner"
  };
}

async function buildLlmSafeLinkQuestion() {
  const seed = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const prompt = `
You are creating a Safe Link Sprint cybersecurity game question.
Return strict JSON only:
{
  "question": "string",
  "context": "string",
  "url": "string",
  "difficulty": "beginner"
}
Rules:
- Scenario must vary each time.
- Use practical, realistic link examples.
- Keep language simple and clear.
- Seed: ${seed}
  `.trim();

  const fallback = buildFallbackSafeLinkQuestion();
  if (!openaiApiKey) return fallback;

  let parsed = null;
  try {
    const response = await fetch("https://api.openai.com/v1/responses", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${openaiApiKey}`
      },
      body: JSON.stringify({
        model: openaiModel,
        input: prompt,
        temperature: 0.35
      })
    });
    if (response.ok) {
      const data = await response.json();
      parsed = extractFirstJsonObject(data.output_text || "");
    }
  } catch {
    parsed = null;
  }

  if (!parsed) return fallback;

  const question = String(parsed.question || fallback.question).slice(0, 220);
  const context = String(parsed.context || fallback.context).slice(0, 240);
  const rawUrl = String(parsed.url || fallback.url).trim();
  const normalized = normalizeUrl(rawUrl);
  const safeUrl = normalized ? normalized.href : fallback.url;
  const evaluated = evaluateSafeLink(safeUrl);

  return {
    question,
    context,
    url: safeUrl,
    options: buildSafeLinkOptions(),
    correctOption: evaluated.correctOption,
    explanation: evaluated.explanation,
    riskScore: evaluated.riskScore,
    riskLevel: evaluated.riskLevel,
    difficulty: "beginner"
  };
}

function buildMalwareOptions() {
  return shuffle([
    { id: "quarantine", text: "Do not run it. Quarantine/delete it and report to security." },
    { id: "scan_first", text: "Scan in a trusted security tool/sandbox before any execution." },
    { id: "run_now", text: "Run it now because the source looks urgent." },
    { id: "disable_security", text: "Turn off antivirus first so installation does not fail." }
  ]);
}

function evaluateMalwareScenario(scenario) {
  const source = String(scenario?.source || "").toLowerCase();
  const fileName = String(scenario?.fileName || "").toLowerCase();
  const requested = String(scenario?.requestedAccess || "").toLowerCase();
  const behavior = String(scenario?.behaviorHint || "").toLowerCase();

  const highRiskHits = [
    /(telegram|whatsapp|discord|unknown|forum|third[- ]party|random)/.test(source),
    /\.(exe|scr|bat|js|vbs|ps1|apk)$/.test(fileName),
    /(macro|powershell|script|admin|accessibility|device admin|root)/.test(requested),
    /(encrypt|ransom|steal|credential|keylog|persistence|command and control|disable security)/.test(behavior)
  ].filter(Boolean).length;

  const mediumRiskHits = [
    /(direct download|email attachment|shared drive)/.test(source),
    /(invoice|urgent|patch|update|free|crack|mod)/.test(fileName),
    /(contacts|sms|call log|overlay|unknown sources|install packages)/.test(requested),
    /(suspicious|unexpected|outbound|hidden process|startup entry)/.test(behavior)
  ].filter(Boolean).length;

  let riskScore = clampPercent((highRiskHits * 26) + (mediumRiskHits * 11));
  if (highRiskHits >= 2 && riskScore < 72) riskScore = 72;
  if (highRiskHits >= 3 && riskScore < 84) riskScore = 84;

  const riskLevel = riskScore >= 70 ? "high" : riskScore >= 40 ? "medium" : "low";
  const correctOption = riskScore >= 60 ? "quarantine" : "scan_first";
  const explanation = correctOption === "quarantine"
    ? `Risk is ${riskScore}% (${riskLevel}). Multiple malware indicators exist. Do not execute; quarantine and report.`
    : `Risk is ${riskScore}% (${riskLevel}). No immediate critical red flags, but scan/sandbox before any execution.`;

  return { riskScore, riskLevel, correctOption, explanation };
}

function buildFallbackMalwareQuestion() {
  const scenarios = [
    {
      context: "A file named urgent_invoice_viewer.exe arrived from an unknown Telegram contact.",
      source: "Unknown Telegram user",
      fileName: "urgent_invoice_viewer.exe",
      requestedAccess: "Asks for admin rights and to disable antivirus.",
      behaviorHint: "Claims urgent payment issue and asks immediate execution."
    },
    {
      context: "You downloaded a cracked game mod from a random forum.",
      source: "Third-party forum download",
      fileName: "premium_patch.bat",
      requestedAccess: "Requests script execution and startup persistence.",
      behaviorHint: "Promises free premium unlock after running script."
    },
    {
      context: "A coworker shared a utility tool from a shared drive with no signature.",
      source: "Internal shared drive (unverified file)",
      fileName: "printer_helper_tool.exe",
      requestedAccess: "Requests normal file access only.",
      behaviorHint: "No urgent pressure but publisher is unknown."
    },
    {
      context: "You found a mobile app APK outside Play Store.",
      source: "Direct download link from social media",
      fileName: "bank_bonus_offer.apk",
      requestedAccess: "Requests SMS, contacts, accessibility, and overlay permissions.",
      behaviorHint: "Asks to allow unknown sources and install quickly."
    }
  ];

  const picked = randomPick(scenarios);
  const evaluated = evaluateMalwareScenario(picked);
  return {
    question: "What is the safest response to this potential malware file?",
    ...picked,
    options: buildMalwareOptions(),
    correctOption: evaluated.correctOption,
    explanation: evaluated.explanation,
    riskScore: evaluated.riskScore,
    riskLevel: evaluated.riskLevel,
    difficulty: "beginner"
  };
}

async function buildLlmMalwareQuestion() {
  const seed = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const prompt = `
You are creating a Malware Defense game scenario for beginners.
Return strict JSON only:
{
  "question": "string",
  "context": "string",
  "source": "string",
  "fileName": "string",
  "requestedAccess": "string",
  "behaviorHint": "string",
  "difficulty": "beginner"
}
Rules:
- Generate realistic malware-defense situations.
- Keep text short and clear.
- Scenario must vary each time.
- Seed: ${seed}
  `.trim();

  const fallback = buildFallbackMalwareQuestion();
  if (!openaiApiKey) return fallback;

  let parsed = null;
  try {
    const response = await fetch("https://api.openai.com/v1/responses", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${openaiApiKey}`
      },
      body: JSON.stringify({
        model: openaiModel,
        input: prompt,
        temperature: 0.35
      })
    });
    if (response.ok) {
      const data = await response.json();
      parsed = extractFirstJsonObject(data.output_text || "");
    }
  } catch {
    parsed = null;
  }

  if (!parsed) return fallback;

  const scenario = {
    question: String(parsed.question || fallback.question).slice(0, 220),
    context: String(parsed.context || fallback.context).slice(0, 240),
    source: String(parsed.source || fallback.source).slice(0, 160),
    fileName: String(parsed.fileName || fallback.fileName).slice(0, 140),
    requestedAccess: String(parsed.requestedAccess || fallback.requestedAccess).slice(0, 220),
    behaviorHint: String(parsed.behaviorHint || fallback.behaviorHint).slice(0, 220),
    difficulty: "beginner"
  };
  const evaluated = evaluateMalwareScenario(scenario);

  return {
    ...scenario,
    options: buildMalwareOptions(),
    correctOption: evaluated.correctOption,
    explanation: evaluated.explanation,
    riskScore: evaluated.riskScore,
    riskLevel: evaluated.riskLevel
  };
}

function buildMalwareChainStages(riskScore) {
  const detectCorrect = riskScore >= 40 ? "detect_suspicious" : "detect_monitor";
  const containCorrect = riskScore >= 70 ? "contain_isolate" : (riskScore >= 40 ? "contain_sandbox" : "contain_monitor");
  const reportCorrect = riskScore >= 40 ? "report_security" : "report_log";

  return [
    {
      key: "detect",
      title: "Step 1 of 3: Detect",
      question: "What is your first triage decision?",
      options: [
        { id: "detect_suspicious", text: "Mark as suspicious and halt execution immediately." },
        { id: "detect_monitor", text: "Treat as low risk and monitor only for now." },
        { id: "detect_run", text: "Run it first to see what happens." }
      ],
      correctOption: detectCorrect,
      explanation: detectCorrect === "detect_suspicious"
        ? "This scenario has enough risk indicators to block execution at triage."
        : "Signals are limited, so controlled monitoring can be acceptable before escalation."
    },
    {
      key: "contain",
      title: "Step 2 of 3: Contain",
      question: "Choose the best containment action.",
      options: [
        { id: "contain_isolate", text: "Isolate/quarantine endpoint and block related artifacts." },
        { id: "contain_sandbox", text: "Detonate in sandbox and scan before any endpoint execution." },
        { id: "contain_monitor", text: "Do not isolate yet; keep observing telemetry only." }
      ],
      correctOption: containCorrect,
      explanation: containCorrect === "contain_isolate"
        ? "High risk requires immediate isolation to prevent spread and data loss."
        : containCorrect === "contain_sandbox"
          ? "Medium risk is best handled with controlled sandbox analysis before execution."
          : "Low-risk signals may be handled through monitoring and routine controls."
    },
    {
      key: "report",
      title: "Step 3 of 3: Report",
      question: "How should this incident be reported?",
      options: [
        { id: "report_security", text: "Escalate to security with IOC/context and user timeline." },
        { id: "report_log", text: "Log the event in ticketing with evidence and close if clean." },
        { id: "report_ignore", text: "No report needed if nothing executed yet." }
      ],
      correctOption: reportCorrect,
      explanation: reportCorrect === "report_security"
        ? "Suspicious malware indicators require formal escalation with evidence."
        : "For low-risk outcomes, documented logging and closure can be appropriate."
    }
  ];
}

async function ensureAnalyzerLogFile() {
  await fs.mkdir(dataDir, { recursive: true });
  try {
    await fs.access(analyzerCsvPath);
  } catch {
    const header = "timestamp,type,user_name,user_email,details\n";
    await fs.writeFile(analyzerCsvPath, header, "utf8");
  }

  try {
    await fs.access(analyzerJsonPath);
  } catch {
    await fs.writeFile(analyzerJsonPath, "[]", "utf8");
  }

  try {
    const logs = await readAnalyzerLogs();
    let changed = false;
    const normalized = logs.map((entry) => {
      if (!entry.id) {
        changed = true;
        return { ...entry, id: generateLogId() };
      }
      return entry;
    });
    if (changed) {
      await writeAnalyzerLogs(normalized);
    }
  } catch {
    await fs.writeFile(analyzerJsonPath, "[]", "utf8");
    await fs.writeFile(analyzerCsvPath, "timestamp,type,user_name,user_email,details\n", "utf8");
  }
}

async function ensureAgentCaseFile() {
  await fs.mkdir(dataDir, { recursive: true });
  try {
    await fs.access(agentCasesJsonPath);
  } catch {
    await fs.writeFile(agentCasesJsonPath, "[]", "utf8");
  }
}

async function readAgentCases() {
  const raw = await fs.readFile(agentCasesJsonPath, "utf8");
  const parsed = JSON.parse(raw);
  return Array.isArray(parsed) ? parsed : [];
}

async function writeAgentCases(cases) {
  await fs.writeFile(agentCasesJsonPath, JSON.stringify(cases), "utf8");
}

async function appendAgentCase(entry) {
  const cases = await readAgentCases();
  cases.push(entry);
  const trimmed = cases.slice(-500);
  await writeAgentCases(trimmed);
}

function withToolTimeout(promise, timeoutMs, label) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error(`${label} timed out`)), timeoutMs))
  ]);
}

async function runWithRetry(taskFn, retries = 1) {
  let lastError;
  for (let i = 0; i <= retries; i += 1) {
    try {
      return await taskFn();
    } catch (err) {
      lastError = err;
      if (i === retries) {
        throw lastError;
      }
    }
  }
  throw lastError || new Error("Task failed");
}

function enforceAgentRateLimit(userEmail) {
  const key = normalizeUserEmail(userEmail);
  const now = Date.now();
  const current = (agentRateWindowByEmail.get(key) || []).filter((ts) => (now - ts) < agentRateWindowMs);
  if (current.length >= agentRateLimitPerWindow) {
    return false;
  }
  current.push(now);
  agentRateWindowByEmail.set(key, current);
  return true;
}

function normalizeAssistantContext(raw) {
  if (!raw || typeof raw !== "object") return null;
  const type = String(raw.analyzerType || "").trim().toLowerCase();
  const analyzerType = ["url", "apk", "email"].includes(type) ? type : "";
  const inputRaw = raw.input && typeof raw.input === "object" ? raw.input : {};
  const analysisRaw = raw.analysis && typeof raw.analysis === "object" ? raw.analysis : null;

  const context = {
    analyzerType,
    input: {
      currentInput: String(inputRaw.currentInput || "").trim().slice(0, 400),
      source: String(inputRaw.source || "").trim().slice(0, 120)
    },
    analysis: null
  };

  if (!analysisRaw) return context;

  const level = String(analysisRaw.riskLevel || "").trim().toLowerCase();
  context.analysis = {
    riskScore: clampPercent(analysisRaw.riskScore),
    confidence: clampPercent(analysisRaw.confidence),
    riskLevel: ["low", "medium", "high"].includes(level) ? level : "low",
    summary: String(analysisRaw.summary || "").trim().slice(0, 320),
    factors: Array.isArray(analysisRaw.factors)
      ? analysisRaw.factors.slice(0, 6).map((item) => ({
        name: String(item?.name || "Signal").trim().slice(0, 80),
        score: clampPercent(item?.score)
      }))
      : []
  };
  return context;
}

function detectAssistantMode(question, context) {
  const text = String(question || "").toLowerCase();
  const type = String(context?.analyzerType || "").toLowerCase();
  if (type) return type;
  if (/https?:\/\/|www\./i.test(text)) return "url";
  if (/\.apk\b|package|install/i.test(text)) return "apk";
  if (/email|subject:|from:|attachment|inbox/i.test(text)) return "email";
  return "general";
}

function buildAssistantFallbackReply(message, rawContext) {
  const question = String(message || "").trim();
  if (!question) {
    return "I could not read your question. Share the URL, APK, or email details and I will give a focused safety check.";
  }

  const context = normalizeAssistantContext(rawContext);
  const mode = detectAssistantMode(question, context);
  const lower = question.toLowerCase();
  const riskScore = Number(context?.analysis?.riskScore || 0);
  const confidence = Number(context?.analysis?.confidence || 0);
  const summary = String(context?.analysis?.summary || "").trim();
  const factors = Array.isArray(context?.analysis?.factors) ? context.analysis.factors : [];
  const factorNames = factors
    .slice()
    .sort((a, b) => Number(b?.score || 0) - Number(a?.score || 0))
    .slice(0, 2)
    .map((f) => String(f?.name || "").trim())
    .filter(Boolean);

  const topSignals = factorNames.length ? factorNames.join(" and ") : "available risk signals";
  const verdict = riskScore >= 70
    ? "high risk"
    : riskScore >= 40
      ? "moderate risk"
      : "low risk";
  const modeAction = mode === "url"
    ? "avoid logging in through that link; open the official site manually"
    : mode === "apk"
      ? "do not install until signature/source checks are complete"
      : mode === "email"
        ? "do not click links or open attachments until sender verification is complete"
        : "pause and verify the source before interacting further";

  if (/\bwhy|reason|how\b/.test(lower)) {
    const reason = summary || `the strongest indicators are ${topSignals}`;
    return `Main reason: ${reason}. Current assessment is ${verdict} (${riskScore}% risk, ${confidence}% confidence). Next step: ${modeAction}.`;
  }

  if (/\b(safe|unsafe|can i|should i|ok to|trust)\b/.test(lower)) {
    if (riskScore >= 70) {
      return `Not safe to proceed right now. Risk is ${riskScore}% with ${confidence}% confidence, and the top signals are ${topSignals}. Recommended action: ${modeAction}.`;
    }
    if (riskScore >= 40) {
      return `Use caution. Risk is ${riskScore}% (${confidence}% confidence). Verify ${topSignals} first, then proceed only if those checks pass.`;
    }
    return `No strong high-risk signal detected (${riskScore}% risk, ${confidence}% confidence), but still verify source and identity before proceeding.`;
  }

  if (/\b(what.*do|next|steps|recommend|action|protect)\b/.test(lower)) {
    return `Do this next: 1) verify source authenticity, 2) validate ${topSignals}, 3) proceed only if checks are clean. Current assessment: ${verdict} (${riskScore}% risk).`;
  }

  if (/\b(confidence|certain|sure|accuracy)\b/.test(lower)) {
    return `Confidence is ${confidence}%. This score reflects signal quality from current inputs; confirm with independent checks before trusting the result.`;
  }

  if (summary) {
    return `Based on your analysis: ${summary} Current rating is ${verdict} (${riskScore}% risk, ${confidence}% confidence). Tell me if you want explanation, safety decision, or exact next steps.`;
  }

  return `I am running in fallback mode. Share the exact ${mode === "general" ? "URL, APK, or email content" : `${mode.toUpperCase()} details`} and I will give a targeted risk explanation.`;
}

async function buildAssistantAiReply(message, context) {
  if (!openaiClient) {
    return { reply: "", error: "OPENAI client unavailable." };
  }

  const systemPrompt = [
    "You are Cyber-Shield AI assistant.",
    "Answer like ChatGPT: natural, clear, and directly tailored to the user's exact question.",
    "For every question, analyze user intent and respond to that exact intent first.",
    "If analyzer context is provided, use its risk score, confidence, summary, and factors in your reasoning.",
    "For cybersecurity questions, include: 1) short direct answer, 2) why (key signals), 3) safest next action.",
    "Do not invent facts that are not in the provided context; if uncertain, say what is unknown.",
    "Avoid harmful or illegal instructions."
  ].join(" ");

  const userContent = context
    ? `User question: ${message}\n\nAnalyzer context:\n${JSON.stringify(context)}`
    : `User question: ${message}`;

  const models = Array.from(new Set(
    [openaiModel, "gpt-4.1-mini", "gpt-4o-mini"]
      .map((m) => String(m || "").trim())
      .filter(Boolean)
  ));

  let lastError = "";
  for (const model of models) {
    try {
      const data = await openaiClient.responses.create({
        model,
        input: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userContent }
        ],
        temperature: 0.25,
        max_output_tokens: 600
      });

      const reply = String(data?.output_text || "").trim();
      if (reply) {
        return { reply, modelUsed: model, error: "" };
      }
      lastError = `${model}: empty response`;
    } catch (err) {
      lastError = `${model}: ${String(err?.message || "request failed")}`;
    }
  }

  return { reply: "", error: lastError || "No model produced a response." };
}

function extractFirstUrl(text) {
  const input = String(text || "");
  const match = input.match(/https?:\/\/[^\s<>"')]+/i);
  return match ? String(match[0]).trim() : "";
}

function extractAssistantInputForMode(question, context, mode) {
  const fromContext = String(context?.input?.currentInput || "").trim();
  const fromQuestion = String(question || "").trim();

  if (mode === "url") {
    return extractFirstUrl(fromContext) || extractFirstUrl(fromQuestion) || fromContext;
  }
  if (mode === "apk") {
    return fromContext || fromQuestion;
  }
  if (mode === "email") {
    return fromContext || fromQuestion;
  }
  return "";
}

async function buildAgenticAssistantContext(question, context) {
  try {
    const mode = detectAssistantMode(question, context);
    if (!["url", "apk", "email"].includes(mode)) {
      return null;
    }

    const input = extractAssistantInputForMode(question, context, mode);
    if (!String(input || "").trim()) {
      return null;
    }

    if (mode === "url") {
      const data = await runUrlAnalysisInternal(input, false);
      return {
        mode,
        input,
        result: data?.result || null,
        sources: data?.sources || null
      };
    }
    if (mode === "apk") {
      const source = String(context?.input?.source || "Unknown").trim() || "Unknown";
      const data = await runApkAnalysisInternal(input, source, false);
      return {
        mode,
        input,
        source,
        result: data?.result || null
      };
    }

    const data = await runEmailAnalysisInternal(input, false);
    return {
      mode,
      inputSnippet: String(input).slice(0, 320),
      result: data?.result || null
    };
  } catch (err) {
    return {
      error: String(err?.message || "Agentic analysis unavailable")
    };
  }
}

async function buildAssistantAiReplyWithFallback(message, context, agenticContext) {
  const mergedContext = agenticContext
    ? { ...(context || {}), agentic: agenticContext }
    : context;

  const primary = await buildAssistantAiReply(message, mergedContext);
  if (primary.reply) return primary;

  if (!openaiClient) {
    return primary;
  }

  const chatModels = Array.from(new Set(
    [openaiModel, "gpt-4.1-mini", "gpt-4o-mini"]
      .map((m) => String(m || "").trim())
      .filter(Boolean)
  ));

  const chatSystem = [
    "You are Cyber-Shield AI assistant.",
    "Answer the user's exact question naturally and clearly.",
    "When agentic analysis exists, use it to support the answer with concrete reasoning.",
    "If something is unknown, say so briefly."
  ].join(" ");

  const chatUser = mergedContext
    ? `User question: ${message}\n\nContext:\n${JSON.stringify(mergedContext)}`
    : `User question: ${message}`;

  let lastError = primary.error || "";
  for (const model of chatModels) {
    try {
      const completion = await openaiClient.chat.completions.create({
        model,
        messages: [
          { role: "system", content: chatSystem },
          { role: "user", content: chatUser }
        ],
        temperature: 0.25
      });
      const reply = String(completion?.choices?.[0]?.message?.content || "").trim();
      if (reply) return { reply, modelUsed: model, error: "" };
      lastError = `${lastError}${lastError ? " | " : ""}${model}: empty chat response`;
    } catch (err) {
      lastError = `${lastError}${lastError ? " | " : ""}${model}: ${String(err?.message || "chat completion failed")}`;
    }
  }

  return { reply: "", error: lastError || "No model produced a response." };
}

async function buildAskAiChatReply(question, messages) {
  if (!openaiClient) {
    return { reply: "", error: "OPENAI client unavailable." };
  }

  const safeQuestion = String(question || "").trim();
  const safeMessages = Array.isArray(messages)
    ? messages
      .filter((m) => m && typeof m === "object")
      .slice(-20)
      .map((m) => ({
        role: String(m.role || "").trim().toLowerCase() === "assistant" ? "assistant" : "user",
        content: String(m.content || "").trim().slice(0, 1600)
      }))
      .filter((m) => m.content)
    : [];

  const inputMessages = safeMessages.length
    ? safeMessages
    : [{ role: "user", content: safeQuestion }];

  const models = Array.from(new Set(
    [openaiModel, "gpt-4.1-mini", "gpt-4o-mini"]
      .map((m) => String(m || "").trim())
      .filter(Boolean)
  ));

  let lastError = "";
  for (const model of models) {
    try {
      const response = await openaiClient.responses.create({
        model,
        input: [
          {
            role: "system",
            content: "Answer the user clearly and directly. If context is missing, ask one concise clarifying question."
          },
          ...inputMessages
        ],
        temperature: 0.35,
        max_output_tokens: 700
      });

      const reply = String(response?.output_text || "").trim();
      if (reply) return { reply, modelUsed: model, error: "" };
      lastError = `${model}: empty response`;
    } catch (err) {
      lastError = `${model}: ${String(err?.message || "request failed")}`;
    }
  }

  return { reply: "", error: lastError || "No model produced a response." };
}

function buildAgentFallbackDecision(objective, providedInput, providedSource, email, stepsTaken, preferredMode) {
  if (stepsTaken >= 1) {
    return { done: true, finalSummary: "Investigation loop completed using fallback decision policy." };
  }
  const text = String(objective || "").toLowerCase();
  const input = String(providedInput || "").trim();
  const mode = String(preferredMode || "").toLowerCase();

  // Respect requested analyzer mode first so APK/Email investigations don't fall back to URL.
  if (mode === "url" && input) {
    return { done: false, tool: "analyzeUrl", args: { url: input }, note: "Fallback: running URL analysis." };
  }
  if (mode === "apk" && input) {
    return { done: false, tool: "analyzeApk", args: { input, source: String(providedSource || "Unknown") }, note: "Fallback: running APK analysis." };
  }
  if (mode === "email" && input) {
    return { done: false, tool: "analyzeEmail", args: { text: input }, note: "Fallback: running email analysis." };
  }

  if (input && (text.includes("url") || /^https?:\/\//i.test(input) || /\bwww\./i.test(input))) {
    return { done: false, tool: "analyzeUrl", args: { url: input }, note: "Fallback: running URL analysis." };
  }
  if (input && (text.includes("apk") || /\.apk$/i.test(input) || isValidApkInput(input))) {
    return { done: false, tool: "analyzeApk", args: { input, source: String(providedSource || "Unknown") }, note: "Fallback: running APK analysis." };
  }
  if (input && (text.includes("email") || input.includes("From:") || input.includes("@"))) {
    return { done: false, tool: "analyzeEmail", args: { text: input }, note: "Fallback: running email analysis." };
  }
  return { done: false, tool: "getUserHistory", args: { email }, note: "Fallback: retrieving user history first." };
}

function sanitizeAgentDecision(raw, fallback) {
  if (!raw || typeof raw !== "object") return fallback;
  const done = Boolean(raw.done);
  const tool = String(raw.tool || "").trim();
  const args = raw.args && typeof raw.args === "object" ? raw.args : {};
  const note = String(raw.note || "").trim();
  const finalSummary = String(raw.finalSummary || "").trim();
  const confidence = clampPercent(raw.confidence);
  const evidence = Array.isArray(raw.evidence) ? raw.evidence.slice(0, 6).map((v) => String(v || "").slice(0, 160)) : [];
  return { done, tool, args, note, finalSummary, confidence, evidence };
}

async function planAgentDecision(payload) {
  const fallback = buildAgentFallbackDecision(
    payload.objective,
    payload.input,
    payload.source,
    payload.email,
    payload.steps.length,
    payload.mode
  );
  if (!openaiClient) return fallback;

  const plannerPrompt = {
    objective: payload.objective,
    input: payload.input,
    source: payload.source,
    userEmail: payload.email,
    previousCases: payload.previousCases,
    availableTools: payload.availableTools,
    toolSchemas: {
      analyzeUrl: { url: "string" },
      analyzeApk: { input: "string", source: "string optional" },
      analyzeEmail: { text: "string" },
      fetchThreatIntel: { kind: "\"url\"|\"apk\"|\"email\"", input: "string" },
      saveCase: { note: "string" },
      getUserHistory: { email: "string optional" }
    },
    rules: [
      "Return strict JSON only.",
      "Choose exactly one tool per step unless done is true.",
      "Do not use tools outside availableTools.",
      "Do not repeat the same analyze tool with the same input unless the previous attempt failed.",
      "Never request delete/export/escalate actions.",
      `Stop within ${agentMaxSteps} steps.`
    ],
    responseSchema: {
      done: "boolean",
      tool: "string when done=false",
      args: "object",
      note: "short string",
      finalSummary: "string when done=true",
      confidence: "0-100 optional",
      evidence: "string[] optional"
    },
    stepsSoFar: payload.steps
  };

  try {
    const response = await openaiClient.responses.create({
      model: openaiModel,
      input: [
        {
          role: "system",
          content: "You are a strict security investigation planner. Output only JSON that follows the schema."
        },
        {
          role: "user",
          content: JSON.stringify(plannerPrompt)
        }
      ],
      temperature: 0.1,
      max_output_tokens: 450
    });
    const parsed = extractFirstJsonObject(String(response?.output_text || ""));
    return sanitizeAgentDecision(parsed, fallback);
  } catch {
    return fallback;
  }
}

async function runUrlAnalysisInternal(urlValue, saveHistory = true) {
  const heuristic = baseUrlHeuristic(urlValue);
  const [openAiSource, virusTotalSource, safeBrowsingSource, githubIntel] = await Promise.all([
    runOpenAiUrlAssessment(urlValue, heuristic),
    evaluateVirusTotalUrl(urlValue),
    evaluateGoogleSafeBrowsing(urlValue),
    evaluateGithubThreatIntel(urlValue)
  ]);
  const githubSource = buildGithubUrlSource(githubIntel);

  const strictErrors = [openAiSource, virusTotalSource, safeBrowsingSource, githubSource]
    .filter((item) => item.error && item.available === false && !/not configured/i.test(item.error))
    .map((item) => `${item.source}: ${item.error}`);
  if (threatIntelStrictMode && strictErrors.length > 0) {
    const err = new Error("One or more threat intelligence sources are unavailable in strict mode.");
    err.status = 503;
    err.detail = strictErrors.join(" | ");
    throw err;
  }

  const result = aggregateUrlRisk([
    { key: "heuristic", source: "Heuristic URL engine", riskScore: heuristic.riskScore, confidence: heuristic.confidence, matched: heuristic.riskScore >= 55, available: true, weight: 0.22 },
    { key: "openai", source: openAiSource.source, riskScore: openAiSource.riskScore, confidence: openAiSource.confidence, matched: openAiSource.matched, available: openAiSource.available, weight: 0.28 },
    { key: "virustotal", source: virusTotalSource.source, riskScore: virusTotalSource.riskScore, confidence: virusTotalSource.confidence, matched: virusTotalSource.matched, available: virusTotalSource.available, weight: 0.25 },
    { key: "gsb", source: safeBrowsingSource.source, riskScore: safeBrowsingSource.riskScore, confidence: safeBrowsingSource.confidence, matched: safeBrowsingSource.matched, available: safeBrowsingSource.available, weight: 0.20 },
    { key: "github", source: githubSource.source, riskScore: githubSource.riskScore, confidence: githubSource.confidence, matched: githubSource.matched, available: githubSource.available, weight: 0.05 }
  ]);

  if (saveHistory) {
    await saveAnalysisHistorySafe("url", { url: urlValue }, result, result?.riskScore || 0);
  }

  return {
    result,
    sources: {
      heuristic: {
        source: "Heuristic URL engine",
        available: true,
        matched: heuristic.riskScore >= 55,
        riskScore: heuristic.riskScore,
        confidence: heuristic.confidence,
        summary: heuristic.summary
      },
      openai: openAiSource,
      virustotal: virusTotalSource,
      safeBrowsing: safeBrowsingSource,
      github: githubSource
    },
    threatFeed: githubIntel.source || null,
    intelMode: threatIntelRealtime ? "realtime" : "cached",
    strictMode: threatIntelStrictMode
  };
}

async function runApkAnalysisInternal(apk, source, saveHistory = true) {
  const normalizedApk = normalizeApkInput(apk);
  if (!isValidApkInput(normalizedApk)) {
    const err = new Error("Invalid APK input. Use package name (com.example.app), SHA-256 hash, APK file name (*.apk), or APK URL.");
    err.status = 400;
    throw err;
  }
  const heuristic = baseApkHeuristic(normalizedApk, source);
  const modelResult = await llmApkAnalysis(normalizedApk, source, heuristic);
  const intel = await evaluateGithubApkThreatIntel(normalizedApk);
  if (threatIntelStrictMode && intel?.error) {
    const err = new Error("APK threat feed unavailable in strict mode.");
    err.status = 503;
    err.detail = intel.error;
    throw err;
  }
  const result = mergeGithubApkIntelRisk(modelResult, intel);
  if (saveHistory) {
    await saveAnalysisHistorySafe("apk", { apk: normalizedApk, source }, result, result?.riskScore || 0);
  }
  return {
    result,
    threatFeed: intel.source || null,
    intelMode: threatIntelRealtime ? "realtime" : "cached",
    strictMode: threatIntelStrictMode
  };
}

async function runEmailAnalysisInternal(emailText, saveHistory = true) {
  const heuristic = baseEmailHeuristic(emailText);
  const modelResult = await llmEmailAnalysis(emailText, heuristic);
  const intel = await evaluateGithubEmailThreatIntel(emailText);
  if (threatIntelStrictMode && intel?.error) {
    const err = new Error("Email threat feed unavailable in strict mode.");
    err.status = 503;
    err.detail = intel.error;
    throw err;
  }
  const result = mergeGithubEmailIntelRisk(modelResult, intel);
  if (saveHistory) {
    await saveAnalysisHistorySafe("email", { emailText }, result, result?.riskScore || 0);
  }
  return {
    result,
    threatFeed: intel.source || null,
    intelMode: threatIntelRealtime ? "realtime" : "cached",
    strictMode: threatIntelStrictMode
  };
}

async function getAgentUserHistory(email) {
  const normalized = normalizeUserEmail(email);
  const logs = (await readAnalyzerLogs())
    .filter((entry) => String(entry.user_email || "").toLowerCase() === normalized)
    .slice(-20)
    .reverse()
    .map((entry) => ({
      id: entry.id || "",
      timestamp: entry.timestamp,
      type: entry.type,
      details: String(entry.details || "").slice(0, 220)
    }));

  const agentCases = (await readAgentCases())
    .filter((entry) => String(entry.user_email || "").toLowerCase() === normalized)
    .slice(-5)
    .reverse()
    .map((entry) => ({
      caseId: entry.caseId,
      timestamp: entry.timestamp,
      summary: String(entry?.report?.summary || "").slice(0, 220),
      riskLevel: String(entry?.report?.riskLevel || "")
    }));

  return { analyzer: logs, investigatorCases: agentCases };
}

function summarizeAgentObservation(output) {
  if (!output || typeof output !== "object") return String(output || "");
  if (output.result && typeof output.result === "object") {
    const result = output.result;
    return `risk=${result.riskScore || 0}% (${result.riskLevel || "unknown"}) confidence=${result.confidence || 0}%`;
  }
  if (Array.isArray(output.analyzer)) {
    return `history loaded (${output.analyzer.length} analyzer rows)`;
  }
  if (output.message) return String(output.message).slice(0, 220);
  return JSON.stringify(output).slice(0, 220);
}

app.get("/api/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, db: "connected" });
  } catch (err) {
    res.status(500).json({ ok: false, message: "DB connection failed", detail: err.message });
  }
});

app.post("/api/analyze-url", async (req, res) => {
  try {
    const urlValue = String(req.body.url || "").trim();
    if (!urlValue) {
      return res.status(400).json({ message: "URL is required." });
    }

    const heuristic = baseUrlHeuristic(urlValue);
    const [openAiSource, virusTotalSource, safeBrowsingSource, githubIntel] = await Promise.all([
      runOpenAiUrlAssessment(urlValue, heuristic),
      evaluateVirusTotalUrl(urlValue),
      evaluateGoogleSafeBrowsing(urlValue),
      evaluateGithubThreatIntel(urlValue)
    ]);
    const githubSource = buildGithubUrlSource(githubIntel);

    const strictErrors = [openAiSource, virusTotalSource, safeBrowsingSource, githubSource]
      .filter((item) => item.error && item.available === false && !/not configured/i.test(item.error))
      .map((item) => `${item.source}: ${item.error}`);
    if (threatIntelStrictMode && strictErrors.length > 0) {
      return res.status(503).json({
        message: "One or more threat intelligence sources are unavailable in strict mode.",
        detail: strictErrors.join(" | ")
      });
    }

    const result = aggregateUrlRisk([
      {
        key: "heuristic",
        source: "Heuristic URL engine",
        riskScore: heuristic.riskScore,
        confidence: heuristic.confidence,
        matched: heuristic.riskScore >= 55,
        available: true,
        weight: 0.22
      },
      {
        key: "openai",
        source: openAiSource.source,
        riskScore: openAiSource.riskScore,
        confidence: openAiSource.confidence,
        matched: openAiSource.matched,
        available: openAiSource.available,
        weight: 0.28
      },
      {
        key: "virustotal",
        source: virusTotalSource.source,
        riskScore: virusTotalSource.riskScore,
        confidence: virusTotalSource.confidence,
        matched: virusTotalSource.matched,
        available: virusTotalSource.available,
        weight: 0.25
      },
      {
        key: "gsb",
        source: safeBrowsingSource.source,
        riskScore: safeBrowsingSource.riskScore,
        confidence: safeBrowsingSource.confidence,
        matched: safeBrowsingSource.matched,
        available: safeBrowsingSource.available,
        weight: 0.20
      },
      {
        key: "github",
        source: githubSource.source,
        riskScore: githubSource.riskScore,
        confidence: githubSource.confidence,
        matched: githubSource.matched,
        available: githubSource.available,
        weight: 0.05
      }
    ]);
    await saveAnalysisHistorySafe(
      "url",
      { url: urlValue },
      result,
      result?.riskScore || 0
    );

    return res.json({
      result,
      sources: {
        heuristic: {
          source: "Heuristic URL engine",
          available: true,
          matched: heuristic.riskScore >= 55,
          riskScore: heuristic.riskScore,
          confidence: heuristic.confidence,
          summary: heuristic.summary
        },
        openai: openAiSource,
        virustotal: virusTotalSource,
        safeBrowsing: safeBrowsingSource,
        github: githubSource
      },
      threatFeed: githubIntel.source || null,
      intelMode: threatIntelRealtime ? "realtime" : "cached",
      strictMode: threatIntelStrictMode
    });
  } catch (err) {
    return res.status(500).json({ message: "URL analysis failed", detail: err.message });
  }
});

app.post("/analyze-url", async (req, res) => {
  try {
    const url = String(req.body.url || "").trim();
    if (!url) {
      return res.status(400).json({ message: "URL is required." });
    }
    const data = await securityAgent(url);
    return res.json(data);
  } catch (err) {
    return res.status(500).json({ message: "URL agent analysis failed", detail: err.message });
  }
});

app.post("/api/analyze-apk", async (req, res) => {
  try {
    const apk = normalizeApkInput(req.body.apk || "");
    const source = String(req.body.source || "Unknown").trim();
    if (!apk) {
      return res.status(400).json({ message: "APK package/hash is required." });
    }
    if (!isValidApkInput(apk)) {
      return res.status(400).json({
        message: "Invalid APK input. Use package name (com.example.app), SHA-256 hash, APK file name (*.apk), or APK URL."
      });
    }

    const heuristic = baseApkHeuristic(apk, source);
    const modelResult = await llmApkAnalysis(apk, source, heuristic);
    const intel = await evaluateGithubApkThreatIntel(apk);
    if (threatIntelStrictMode && intel?.error) {
      return res.status(503).json({ message: "APK threat feed unavailable in strict mode.", detail: intel.error });
    }
    const result = mergeGithubApkIntelRisk(modelResult, intel);
    await saveAnalysisHistorySafe(
      "apk",
      { apk, source },
      result,
      result?.riskScore || 0
    );
    return res.json({
      result,
      threatFeed: intel.source || null,
      intelMode: threatIntelRealtime ? "realtime" : "cached",
      strictMode: threatIntelStrictMode
    });
  } catch (err) {
    return res.status(500).json({ message: "APK analysis failed", detail: err.message });
  }
});

app.post("/api/analyze-email", async (req, res) => {
  try {
    const emailText = String(req.body.emailText || "").trim();
    if (!emailText) {
      return res.status(400).json({ message: "Email text is required." });
    }

    const heuristic = baseEmailHeuristic(emailText);
    const modelResult = await llmEmailAnalysis(emailText, heuristic);
    const intel = await evaluateGithubEmailThreatIntel(emailText);
    if (threatIntelStrictMode && intel?.error) {
      return res.status(503).json({ message: "Email threat feed unavailable in strict mode.", detail: intel.error });
    }
    const result = mergeGithubEmailIntelRisk(modelResult, intel);
    await saveAnalysisHistorySafe(
      "email",
      { emailText },
      result,
      result?.riskScore || 0
    );
    return res.json({
      result,
      threatFeed: intel.source || null,
      intelMode: threatIntelRealtime ? "realtime" : "cached",
      strictMode: threatIntelStrictMode
    });
  } catch (err) {
    return res.status(500).json({ message: "Email analysis failed", detail: err.message });
  }
});

app.post("/api/llm-assistant", async (req, res) => {
  try {
    const message = String(req.body.message || "").trim();
    const context = normalizeAssistantContext(req.body.context);
    if (!message) {
      return res.status(400).json({ message: "Message is required." });
    }
    if (message.length > 1600) {
      return res.status(400).json({ message: "Message is too long. Keep it under 1600 characters." });
    }
    const ollamaUrl = (process.env.OLLAMA_URL || "http://localhost:11434").trim().replace(/\/+$/, "");
    const ollamaModel = (process.env.OLLAMA_MODEL || "phi3").trim();

    if (!openaiClient) {
      const ollamaPrompt = `You are a cybersecurity expert.
Respond suddenly: short, direct, and urgent.
Use 1-3 short sentences. Start with the core risk first.
No greeting, no filler.

User question: ${message.slice(0, 1600)}`;
      const ollamaResponse = await axios.post(`${ollamaUrl}/api/generate`, {
        model: ollamaModel,
        prompt: ollamaPrompt,
        stream: false
      });
      const ollamaReply = String(ollamaResponse?.data?.response || "").trim();
      if (!ollamaReply) {
        return res.status(502).json({ message: "AI could not generate a response.", detail: "Empty response from Ollama." });
      }
      return res.json({
        reply: ollamaReply,
        modelUsed: ollamaModel,
        usedAgentic: false
      });
    }

    const agenticContext = await buildAgenticAssistantContext(message, context);
    const ai = await buildAssistantAiReplyWithFallback(message, context, agenticContext);
    if (ai.reply) {
      return res.json({
        reply: ai.reply,
        modelUsed: ai.modelUsed || openaiModel,
        usedAgentic: Boolean(agenticContext && !agenticContext.error)
      });
    }

    const ollamaPrompt = `You are a cybersecurity expert.
Respond suddenly: short, direct, and urgent.
Use 1-3 short sentences. Start with the core risk first.
No greeting, no filler.

User question: ${message.slice(0, 1600)}`;
    const ollamaResponse = await axios.post(`${ollamaUrl}/api/generate`, {
      model: ollamaModel,
      prompt: ollamaPrompt,
      stream: false
    });
    const ollamaReply = String(ollamaResponse?.data?.response || "").trim();
    if (!ollamaReply) {
      return res.status(502).json({ message: "AI could not generate a response.", detail: ai.error || "Empty response from Ollama." });
    }

    return res.json({
      reply: ollamaReply,
      modelUsed: ollamaModel,
      usedAgentic: false
    });
  } catch (err) {
    return res.status(500).json({ message: "AI assistant failed.", detail: String(err?.message || "Unknown LLM error") });
  }
});

app.post("/ask-ai", async (req, res) => {
  try {
    const question = String(req.body?.question || "").trim();
    if (!question) {
      return res.status(400).json({ error: "question is required" });
    }
    const ollamaUrl = (process.env.OLLAMA_URL || "http://localhost:11434").trim().replace(/\/+$/, "");
    const ollamaModel = (process.env.OLLAMA_MODEL || "phi3").trim();
    const ollamaPrompt = `You are a cybersecurity expert.
Respond suddenly: short, direct, and urgent.
Use 1-3 short sentences. Start with the core risk first.
No greeting, no filler.

User question: ${question.slice(0, 1600)}`;
    const response = await axios.post(`${ollamaUrl}/api/generate`, {
      model: ollamaModel,
      prompt: ollamaPrompt,
      stream: false
    });
    const answer = String(response?.data?.response || "").trim();
    if (!answer) {
      return res.status(502).json({ error: "AI failed", detail: "Empty response from Ollama." });
    }
    return res.json({ answer });
  } catch (error) {
    return res.status(500).json({ error: "AI failed", detail: String(error?.message || "Unknown error from Ollama") });
  }
});

app.post("/api/agent/investigate", async (req, res) => {
  try {
    const objective = String(req.body.objective || "").trim();
    const email = normalizeUserEmail(req.body.email || "");
    const mode = String(req.body.mode || "auto").trim().toLowerCase();
    const input = String(req.body.input || "").trim();
    const source = String(req.body.source || "Unknown").trim();

    if (!objective) {
      return res.status(400).json({ message: "Objective is required." });
    }
    if (objective.length > 1600) {
      return res.status(400).json({ message: "Objective is too long. Keep it under 1600 characters." });
    }
    if (/\b(delete|export|wipe|escalate)\b/i.test(objective)) {
      return res.status(403).json({
        message: "High-impact objective requires human approval.",
        requiresApproval: true
      });
    }
    if (!enforceAgentRateLimit(email)) {
      return res.status(429).json({ message: "Rate limit exceeded. Try again in a minute." });
    }

    const availableTools = ["analyzeUrl", "analyzeApk", "analyzeEmail", "fetchThreatIntel", "saveCase", "getUserHistory"];
    const previousCases = (await readAgentCases())
      .filter((entry) => String(entry.user_email || "").toLowerCase() === email)
      .slice(-3)
      .map((entry) => ({
        caseId: entry.caseId,
        timestamp: entry.timestamp,
        summary: String(entry?.report?.summary || "").slice(0, 220),
        riskLevel: entry?.report?.riskLevel || ""
      }));

    const steps = [];
    const notes = [];
    const analysisResults = [];
    let plannerFinalSummary = "";
    let plannerConfidence = 0;
    let plannerEvidence = [];

    for (let i = 0; i < agentMaxSteps; i += 1) {
      const plan = await planAgentDecision({
        objective,
        email,
        mode,
        input,
        source,
        previousCases,
        availableTools,
        steps
      });

      if (plan.done) {
        plannerFinalSummary = String(plan.finalSummary || "").trim();
        plannerConfidence = clampPercent(plan.confidence || plannerConfidence);
        plannerEvidence = Array.isArray(plan.evidence) ? plan.evidence : plannerEvidence;
        steps.push({
          step: i + 1,
          action: "finish",
          status: "completed",
          note: plan.note || "Planner marked investigation as complete.",
          observation: plannerFinalSummary || "Final summary ready."
        });
        break;
      }

      const highImpactTool = new Set(["deleteData", "exportData", "escalateIncident"]);
      if (highImpactTool.has(plan.tool)) {
        steps.push({
          step: i + 1,
          action: plan.tool,
          status: "needs_approval",
          note: "High-impact action requires human approval.",
          observation: "Planner requested a protected operation."
        });
        plannerFinalSummary = "Investigation paused because a high-impact action needs human approval.";
        break;
      }

      if (!availableTools.includes(plan.tool)) {
        steps.push({
          step: i + 1,
          action: plan.tool || "unknown",
          status: "rejected",
          note: "Tool not allowlisted.",
          observation: "Planner requested a blocked tool."
        });
        continue;
      }

      let observation = null;
      try {
        if (plan.tool === "analyzeUrl") {
          if (analysisResults.some((item) => item.kind === "url")) {
            steps.push({
              step: i + 1,
              action: plan.tool,
              status: "skipped",
              note: "Duplicate URL analysis avoided.",
              args: plan.args || {},
              observation: "Using previous URL analysis result."
            });
            plannerFinalSummary = plannerFinalSummary || "Investigation completed using the first successful URL analysis result.";
            break;
          }
          const urlValue = String(plan.args?.url || input || "").trim();
          if (!urlValue) throw new Error("analyzeUrl requires args.url");
          observation = await runWithRetry(
            () => withToolTimeout(runUrlAnalysisInternal(urlValue, false), agentToolTimeoutMs, "analyzeUrl"),
            1
          );
          analysisResults.push({ kind: "url", result: observation.result });
        } else if (plan.tool === "analyzeApk") {
          if (analysisResults.some((item) => item.kind === "apk")) {
            steps.push({
              step: i + 1,
              action: plan.tool,
              status: "skipped",
              note: "Duplicate APK analysis avoided.",
              args: plan.args || {},
              observation: "Using previous APK analysis result."
            });
            plannerFinalSummary = plannerFinalSummary || "Investigation completed using the first successful APK analysis result.";
            break;
          }
          const apkInput = String(plan.args?.input || input || "").trim();
          const apkSource = String(plan.args?.source || source || "Unknown").trim();
          if (!apkInput) throw new Error("analyzeApk requires args.input");
          observation = await runWithRetry(
            () => withToolTimeout(runApkAnalysisInternal(apkInput, apkSource, false), agentToolTimeoutMs, "analyzeApk"),
            1
          );
          analysisResults.push({ kind: "apk", result: observation.result });
        } else if (plan.tool === "analyzeEmail") {
          if (analysisResults.some((item) => item.kind === "email")) {
            steps.push({
              step: i + 1,
              action: plan.tool,
              status: "skipped",
              note: "Duplicate email analysis avoided.",
              args: plan.args || {},
              observation: "Using previous email analysis result."
            });
            plannerFinalSummary = plannerFinalSummary || "Investigation completed using the first successful email analysis result.";
            break;
          }
          const emailText = String(plan.args?.text || input || "").trim();
          if (!emailText) throw new Error("analyzeEmail requires args.text");
          observation = await runWithRetry(
            () => withToolTimeout(runEmailAnalysisInternal(emailText, false), agentToolTimeoutMs, "analyzeEmail"),
            1
          );
          analysisResults.push({ kind: "email", result: observation.result });
        } else if (plan.tool === "fetchThreatIntel") {
          const kind = String(plan.args?.kind || mode || "").toLowerCase();
          const rawInput = String(plan.args?.input || input || "").trim();
          if (!rawInput) throw new Error("fetchThreatIntel requires args.input");
          if (kind === "url") {
            const intel = await runWithRetry(
              () => withToolTimeout(evaluateGithubThreatIntel(rawInput), agentToolTimeoutMs, "fetchThreatIntel-url"),
              1
            );
            observation = { kind: "url", message: intel?.matched ? "Threat feed matched URL/domain." : "No threat feed match.", intel };
          } else if (kind === "apk") {
            const intel = await runWithRetry(
              () => withToolTimeout(evaluateGithubApkThreatIntel(rawInput), agentToolTimeoutMs, "fetchThreatIntel-apk"),
              1
            );
            observation = { kind: "apk", message: intel?.matched ? "Threat feed matched hash/package." : "No threat feed match.", intel };
          } else {
            const intel = await runWithRetry(
              () => withToolTimeout(evaluateGithubEmailThreatIntel(rawInput), agentToolTimeoutMs, "fetchThreatIntel-email"),
              1
            );
            observation = { kind: "email", message: intel?.matched ? "Threat feed matched indicators." : "No threat feed match.", intel };
          }
        } else if (plan.tool === "saveCase") {
          const note = String(plan.args?.note || "").trim();
          if (!note) throw new Error("saveCase requires args.note");
          notes.push(note.slice(0, 300));
          observation = { message: "Case note saved in memory." };
        } else if (plan.tool === "getUserHistory") {
          const historyEmail = normalizeUserEmail(plan.args?.email || email);
          const isAdmin = email === appAdminEmail;
          if (!isAdmin && historyEmail !== email) {
            throw new Error("Permission denied for other user history.");
          }
          observation = await runWithRetry(
            () => withToolTimeout(getAgentUserHistory(historyEmail), agentToolTimeoutMs, "getUserHistory"),
            1
          );
        }

        steps.push({
          step: i + 1,
          action: plan.tool,
          status: "completed",
          note: String(plan.note || "").slice(0, 220),
          args: plan.args || {},
          observation: summarizeAgentObservation(observation)
        });
      } catch (toolErr) {
        steps.push({
          step: i + 1,
          action: plan.tool,
          status: "failed",
          note: String(plan.note || "").slice(0, 220),
          args: plan.args || {},
          observation: String(toolErr?.message || "Tool execution failed.")
        });
      }
    }

    const topResult = analysisResults
      .map((item) => ({ kind: item.kind, ...(item.result || {}) }))
      .sort((a, b) => Number(b.riskScore || 0) - Number(a.riskScore || 0))[0] || null;

    const riskScore = clampPercent(topResult?.riskScore || 0);
    const riskLevel = String(topResult?.riskLevel || riskLevelFromScore(riskScore));
    const confidence = clampPercent(topResult?.confidence || plannerConfidence || 0);
    const evidence = [
      ...(Array.isArray(topResult?.factors) ? topResult.factors.map((f) => `${f.name}: ${f.score}%`) : []),
      ...steps.filter((s) => s.status === "completed").map((s) => `Step ${s.step} ${s.action}: ${s.observation}`),
      ...plannerEvidence
    ].slice(0, 8);

    const recommendations = riskScore >= 70
      ? ["Do not open/click/install yet.", "Isolate item and escalate to security.", "Preserve indicators and timeline evidence."]
      : riskScore >= 40
        ? ["Run additional verification and sandbox checks.", "Confirm sender/domain/signature via trusted source.", "Proceed only after manual review."]
        : ["No strong high-risk signal found.", "Continue with normal caution and verify authenticity.", "Monitor for behavior changes or new intel."]
      ;

    const report = {
      summary: plannerFinalSummary || topResult?.summary || "Investigation completed with available tools.",
      riskScore,
      riskLevel,
      confidence,
      evidence,
      recommendations
    };

    const caseId = `case_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
    const timestamp = new Date().toISOString();
    await appendAgentCase({
      caseId,
      timestamp,
      user_email: email,
      objective,
      request: { mode, input, source },
      steps,
      notes,
      report
    });

    return res.json({
      caseId,
      timestamp,
      steps,
      report
    });
  } catch (err) {
    const status = Number(err?.status || 500);
    return res.status(status).json({
      message: err?.message || "Agent investigation failed.",
      detail: err?.detail || ""
    });
  }
});

app.post("/api/llm/url-risk", async (req, res) => {
  try {
    const urlValue = String(req.body.url || "").trim();
    if (!urlValue) {
      return res.status(400).json({ message: "URL is required." });
    }
    if (!openaiClient) {
      return res.status(503).json({ message: "OPENAI_API_KEY is not configured." });
    }

    const response = await openaiClient.responses.create({
      model: "gpt-4.1",
      input: `Analyze this URL for phishing risk: ${urlValue}`
    });

    return res.json({ text: String(response?.output_text || "").trim() });
  } catch (err) {
    return res.status(500).json({ message: "LLM URL risk analysis failed", detail: err.message });
  }
});


app.post("/api/signup", async (req, res) => {
  try {
    const name = (req.body.name || "").trim();
    const email = (req.body.email || "").trim().toLowerCase();
    const password = req.body.password || "";
    const username = name || email.split("@")[0] || "user";

    if (!name || !email || !password) {
      return res.status(400).json({ message: "Name, email, and password are required." });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters." });
    }

    if (!isEmailFormatValid(email)) {
      return res.status(400).json({ message: "Enter a valid email address." });
    }

    if (isDisposableEmailDomain(email)) {
      return res.status(400).json({ message: "Disposable email addresses are not allowed." });
    }

    const [existing] = await pool.query(
      `SELECT id FROM \`${usersTable}\` WHERE email = ? LIMIT 1`,
      [email]
    );
    if (existing.length > 0) {
      return res.status(409).json({ message: "Email already registered. Please login." });
    }

    const hashed = await bcrypt.hash(password, 10);
    await pool.query(
      `INSERT INTO \`${usersTable}\` (username, name, email, password)
       VALUES (?, ?, ?, ?)`,
      [username, name, email, hashed]
    );

    const [fresh] = await pool.query(
      `SELECT id, username, name, email FROM \`${usersTable}\` WHERE email = ? LIMIT 1`,
      [email]
    );
    const user = fresh[0] || { id: 0, name, username, email };

    return res.status(201).json({
      message: "Signup successful.",
      user: { id: user.id, name: user.name || name, username: user.username || username, email: user.email || email }
    });
  } catch (err) {
    return res.status(500).json({ message: "Signup failed", detail: err.message });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const email = (req.body.email || "").trim().toLowerCase();
    const password = req.body.password || "";
    const loginMeta = {
      clientLoginDate: req.body.clientLoginDate,
      clientLoginTime: req.body.clientLoginTime,
      clientTimeZone: req.body.clientTimeZone
    };

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required." });
    }

    if (email === appAdminEmail && password === appAdminPassword) {
      const adminUser = { id: 0, name: "Admin", username: "admin", email: appAdminEmail };
      await recordLoginAuditSafe(req, adminUser, loginMeta);
      const loginAt = new Date().toISOString();
      return res.json({
        message: "Login successful",
        user: adminUser,
        isAdmin: true,
        loginAt
      });
    }

    const [rows] = await pool.query(
      `SELECT id, username, name, email, password
       FROM \`${usersTable}\` WHERE email = ? LIMIT 1`,
      [email]
    );

    if (rows.length === 0) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    const dbUser = rows[0];
    const passOk = await bcrypt.compare(password, dbUser.password);

    if (!passOk) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    await recordLoginAuditSafe(req, dbUser, loginMeta);
    const loginAt = new Date().toISOString();

    return res.json({
      message: "Login successful",
      user: { id: dbUser.id, name: dbUser.name || dbUser.username || "User", username: dbUser.username || "", email: dbUser.email },
      isAdmin: false,
      loginAt
    });
  } catch (err) {
    return res.status(500).json({ message: "Login failed", detail: err.message });
  }
});

app.post("/api/delete-account", async (req, res) => {
  try {
    const email = (req.body.email || "").trim().toLowerCase();

    if (!email) {
      return res.status(400).json({ message: "Email is required." });
    }

    const [result] = await pool.query(`DELETE FROM \`${usersTable}\` WHERE email = ? LIMIT 1`, [email]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Account not found." });
    }

    await pool.query("DELETE FROM game_scores WHERE user_email = ?", [email]);
    return res.json({ message: "Account deleted successfully." });
  } catch (err) {
    return res.status(500).json({ message: "Delete account failed", detail: err.message });
  }
});

app.post("/api/analyzer-log", async (req, res) => {
  try {
    const type = String(req.body.type || "").trim().toLowerCase();
    const details = String(req.body.details || "").trim();
    const userName = String(req.body.userName || "Unknown").trim();
    const userEmail = String(req.body.userEmail || "guest@local").trim().toLowerCase();

    if (!["url", "apk", "email"].includes(type)) {
      return res.status(400).json({ message: "Invalid analyzer type." });
    }
    if (!details) {
      return res.status(400).json({ message: "Analyzer details are required." });
    }

    const timestamp = new Date().toISOString();
    const logs = await readAnalyzerLogs();
    logs.push({
      id: generateLogId(),
      timestamp,
      type,
      user_name: userName,
      user_email: userEmail,
      details
    });
    await writeAnalyzerLogs(logs);
    return res.status(201).json({ message: "Analyzer data saved." });
  } catch (err) {
    return res.status(500).json({ message: "Failed to save analyzer data", detail: err.message });
  }
});

app.get("/api/analyzer-log/mine", async (req, res) => {
  try {
    const email = String(req.query.email || "").trim().toLowerCase();
    if (!email) {
      return res.status(400).json({ message: "Email is required." });
    }

    const isAdminRequest = email === appAdminEmail;
    const rawRows = (await readAnalyzerLogs())
      .filter((entry) => isAdminRequest || String(entry.user_email || "").toLowerCase() === email)
      .slice(-200)
      .reverse()
      .map((entry) => ({
        id: entry.id || "",
        timestamp: entry.timestamp,
        type: entry.type,
        userName: String(entry.user_name || "").trim(),
        userEmail: String(entry.user_email || "").trim().toLowerCase(),
        details: entry.details
      }));

    const emailSet = new Set(rawRows.map((row) => row.userEmail).filter(Boolean));
    const emails = Array.from(emailSet);
    const usernameByEmail = new Map();

    if (emails.length > 0) {
      const placeholders = emails.map(() => "?").join(",");
      const [userRows] = await pool.query(
        `SELECT email, username
         FROM \`${usersTable}\`
         WHERE LOWER(COALESCE(email, "")) IN (${placeholders})`,
        emails
      );
      (userRows || []).forEach((u) => {
        const k = String(u.email || "").trim().toLowerCase();
        const v = String(u.username || "").trim();
        if (k) usernameByEmail.set(k, v);
      });
    }

    const rows = rawRows.map((row) => ({
      ...row,
      username: usernameByEmail.get(row.userEmail) || ""
    }));

    return res.json({ rows });
  } catch (err) {
    return res.status(500).json({ message: "Failed to load analyzer data", detail: err.message });
  }
});

app.delete("/api/analyzer-log/:id", async (req, res) => {
  try {
    const id = String(req.params.id || "").trim();
    const email = String(req.query.email || "").trim().toLowerCase();
    if (!id || !email) {
      return res.status(400).json({ message: "Log id and email are required." });
    }

    const isAdminRequest = email === appAdminEmail;
    const logs = await readAnalyzerLogs();
    const next = logs.filter((entry) => {
      const idMatches = String(entry.id || "") === id;
      if (!idMatches) return true;
      if (isAdminRequest) return false;
      return String(entry.user_email || "").toLowerCase() !== email;
    });
    if (next.length === logs.length) {
      return res.status(404).json({ message: "Record not found." });
    }
    await writeAnalyzerLogs(next);
    return res.json({ message: "Record deleted." });
  } catch (err) {
    return res.status(500).json({ message: "Failed to delete record", detail: err.message });
  }
});

app.post("/api/analyzer-log/delete-many", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const ids = Array.isArray(req.body.ids) ? req.body.ids.map((v) => String(v)) : [];
    if (!email || ids.length === 0) {
      return res.status(400).json({ message: "Email and ids are required." });
    }

    const isAdminRequest = email === appAdminEmail;
    const idSet = new Set(ids);
    const logs = await readAnalyzerLogs();
    const next = logs.filter((entry) => {
      const targetId = idSet.has(String(entry.id || ""));
      if (!targetId) return true;
      if (isAdminRequest) return false;
      return String(entry.user_email || "").toLowerCase() !== email;
    });
    const deleted = logs.length - next.length;
    if (deleted === 0) {
      return res.status(404).json({ message: "No matching records found." });
    }
    await writeAnalyzerLogs(next);
    return res.json({ message: "Records deleted.", deleted });
  } catch (err) {
    return res.status(500).json({ message: "Failed to delete records", detail: err.message });
  }
});

app.get("/api/admin/analyzer-export", async (req, res) => {
  try {
    const key = String(req.query.key || req.header("x-admin-key") || "").trim();
    if (!key || key !== adminExportKey) {
      return res.status(403).json({ message: "Forbidden: invalid admin key." });
    }

    const content = await fs.readFile(analyzerCsvPath, "utf8");
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", "attachment; filename=\"analyzer_logs.csv\"");
    return res.status(200).send(content);
  } catch (err) {
    return res.status(500).json({ message: "Failed to export analyzer data", detail: err.message });
  }
});

app.get("/api/admin/leaderboard-export", async (req, res) => {
  try {
    const key = String(req.query.key || req.header("x-admin-key") || "").trim();
    if (!key || key !== adminExportKey) {
      return res.status(403).json({ message: "Forbidden: invalid admin key." });
    }

    const [rows] = await pool.query(
      `SELECT
         user_name AS userName,
         user_email AS userEmail,
         COALESCE(MAX(u.username), "") AS username,
         COUNT(*) AS runs,
         ROUND(AVG(score), 1) AS avgScore,
         MAX(score) AS bestScore
       FROM game_scores gs
       LEFT JOIN \`${usersTable}\` u ON LOWER(COALESCE(u.email, "")) = gs.user_email
       GROUP BY user_email, user_name
       ORDER BY avgScore DESC, bestScore DESC, runs DESC
       LIMIT 1000`
    );

    const header = "rank,user_name,username,user_email,runs,avg_score,best_score\n";
    const body = (rows || []).map((row, idx) => ([
      idx + 1,
      row.userName,
      row.username,
      row.userEmail,
      row.runs,
      row.avgScore,
      row.bestScore
    ].map(csvEscape).join(","))).join("\n");
    const content = `${header}${body}${body ? "\n" : ""}`;

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", "attachment; filename=\"leaderboard_export.csv\"");
    return res.status(200).send(content);
  } catch (err) {
    return res.status(500).json({ message: "Failed to export leaderboard data", detail: err.message });
  }
});


app.post("/api/game-score", async (req, res) => {
  try {
    let userName = String(req.body.userName || "User").trim() || "User";
    const userEmail = String(req.body.userEmail || "").trim().toLowerCase();
    const gameKey = String(req.body.gameKey || "").trim().toLowerCase();
    const score = Math.max(0, Math.round(Number(req.body.score || 0)));
    const accuracy = Math.max(0, Math.min(100, Number(req.body.accuracy || 0)));
    const correctCount = Math.max(0, Math.round(Number(req.body.correctCount || 0)));
    const totalQuestions = Math.max(0, Math.round(Number(req.body.totalQuestions || 0)));
    const durationSeconds = Math.max(0, Math.round(Number(req.body.durationSeconds || 0)));

    if (!userEmail) {
      return res.status(400).json({ message: "User email is required." });
    }
    if (!allowedGameKeys.has(gameKey)) {
      return res.status(400).json({ message: "Invalid game key." });
    }

    if (userName === "User" || userName === "Unknown") {
      const [ownerRows] = await pool.query(
        `SELECT COALESCE(NULLIF(name, ''), NULLIF(username, ''), 'User') AS displayName
         FROM \`${usersTable}\`
         WHERE email = ?
         LIMIT 1`,
        [userEmail]
      );
      userName = String(ownerRows?.[0]?.displayName || userName).trim() || "User";
    }

    const [scoreInsert] = await pool.query(
      `INSERT INTO game_scores
      (user_name, user_email, game_key, score, accuracy, correct_count, total_questions, duration_seconds)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [userName.slice(0, 120), userEmail.slice(0, 190), gameKey, score, accuracy, correctCount, totalQuestions, durationSeconds]
    );

    await pool.query(
      `INSERT INTO leaderboard (username, email, score, scans_completed, threats_detected, source_game_score_id)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [
        userName.slice(0, 100),
        userEmail.slice(0, 150),
        score,
        totalQuestions,
        correctCount,
        Number(scoreInsert?.insertId || 0) || null
      ]
    );

    return res.status(201).json({ message: "Score saved." });
  } catch (err) {
    return res.status(500).json({ message: "Failed to save game score", detail: err.message });
  }
});

app.get("/api/game-score/board", async (req, res) => {
  try {
    const email = String(req.query.email || "").trim().toLowerCase();
    const requestedGameKey = String(req.query.gameKey || "all").trim().toLowerCase();
    const gameKey = requestedGameKey === "all" ? "all" : requestedGameKey;
    const isAdminBoardView = email === appAdminEmail;

    if (!email) {
      return res.status(400).json({ message: "Email is required." });
    }
    if (gameKey !== "all" && !allowedGameKeys.has(gameKey)) {
      return res.status(400).json({ message: "Invalid game key." });
    }

    const [summaryRows] = await pool.query(
      `SELECT
        COUNT(*) AS runs,
        ROUND(AVG(score), 1) AS avgScore,
        COALESCE(MAX(score), 0) AS bestScore,
        COUNT(DISTINCT game_key) AS gamesPlayed
      FROM game_scores
      WHERE user_email = ?`,
      [email]
    );

    const historySql = gameKey === "all"
      ? `SELECT game_key AS gameKey, score, accuracy, correct_count AS correctCount,
           total_questions AS totalQuestions, duration_seconds AS durationSeconds, created_at AS createdAt
         FROM game_scores
         WHERE user_email = ?
         ORDER BY created_at ASC
         LIMIT 60`
      : `SELECT game_key AS gameKey, score, accuracy, correct_count AS correctCount,
           total_questions AS totalQuestions, duration_seconds AS durationSeconds, created_at AS createdAt
         FROM game_scores
         WHERE user_email = ? AND game_key = ?
         ORDER BY created_at ASC
         LIMIT 60`;
    const historyParams = gameKey === "all" ? [email] : [email, gameKey];
    const [historyRows] = await pool.query(historySql, historyParams);

    const recentSql = isAdminBoardView
      ? `SELECT
           gs.user_name AS userName,
           gs.user_email AS userEmail,
           COALESCE(u.username, "") AS username,
           gs.game_key AS gameKey,
           gs.score AS score,
           gs.accuracy AS accuracy,
           gs.correct_count AS correctCount,
           gs.total_questions AS totalQuestions,
           gs.duration_seconds AS durationSeconds,
           gs.created_at AS createdAt
         FROM game_scores gs
         LEFT JOIN \`${usersTable}\` u ON LOWER(COALESCE(u.email, "")) = gs.user_email
         ORDER BY gs.created_at DESC
         LIMIT 20`
      : `SELECT
           gs.user_name AS userName,
           gs.user_email AS userEmail,
           COALESCE(u.username, "") AS username,
           gs.game_key AS gameKey,
           gs.score AS score,
           gs.accuracy AS accuracy,
           gs.correct_count AS correctCount,
           gs.total_questions AS totalQuestions,
           gs.duration_seconds AS durationSeconds,
           gs.created_at AS createdAt
         FROM game_scores gs
         LEFT JOIN \`${usersTable}\` u ON LOWER(COALESCE(u.email, "")) = gs.user_email
         WHERE gs.user_email = ?
         ORDER BY gs.created_at DESC
         LIMIT 8`;
    const recentParams = isAdminBoardView ? [] : [email];
    const [recentRows] = await pool.query(recentSql, recentParams);

    const leaderboardSql = gameKey === "all"
      ? `SELECT
           gs.user_name AS userName,
           gs.user_email AS userEmail,
           COALESCE(MAX(u.username), "") AS username,
           COUNT(*) AS runs,
           ROUND(AVG(score), 1) AS avgScore,
           MAX(score) AS bestScore
         FROM game_scores gs
         LEFT JOIN \`${usersTable}\` u ON LOWER(COALESCE(u.email, "")) = gs.user_email
         GROUP BY gs.user_email, gs.user_name
         ORDER BY avgScore DESC, bestScore DESC, runs DESC
         LIMIT 20`
      : `SELECT
           gs.user_name AS userName,
           gs.user_email AS userEmail,
           COALESCE(MAX(u.username), "") AS username,
           COUNT(*) AS runs,
           ROUND(AVG(score), 1) AS avgScore,
           MAX(score) AS bestScore
         FROM game_scores gs
         LEFT JOIN \`${usersTable}\` u ON LOWER(COALESCE(u.email, "")) = gs.user_email
         WHERE gs.game_key = ?
         GROUP BY gs.user_email, gs.user_name
         ORDER BY avgScore DESC, bestScore DESC, runs DESC
         LIMIT 20`;
    const leaderboardParams = gameKey === "all" ? [] : [gameKey];
    const [leaderboardRows] = await pool.query(leaderboardSql, leaderboardParams);

    return res.json({
      summary: summaryRows?.[0] || { runs: 0, avgScore: 0, bestScore: 0, gamesPlayed: 0 },
      history: historyRows || [],
      recent: recentRows || [],
      leaderboard: leaderboardRows || []
    });
  } catch (err) {
    return res.status(500).json({ message: "Failed to load game leaderboard", detail: err.message });
  }
});

app.get("/api/game-score/my", async (req, res) => {
  try {
    const email = String(req.query.email || "").trim().toLowerCase();
    if (!email) {
      return res.status(400).json({ message: "Email is required." });
    }

    const [summaryRows] = await pool.query(
      `SELECT
        COUNT(*) AS runs,
        ROUND(AVG(score), 1) AS avgScore,
        COALESCE(MAX(score), 0) AS bestScore,
        COUNT(DISTINCT game_key) AS gamesPlayed
      FROM game_scores
      WHERE user_email = ?`,
      [email]
    );

    const [recentRows] = await pool.query(
      `SELECT game_key AS gameKey, score, accuracy, created_at AS createdAt
       FROM game_scores
       WHERE user_email = ?
       ORDER BY created_at DESC
       LIMIT 20`,
      [email]
    );

    return res.json({
      summary: summaryRows?.[0] || { runs: 0, avgScore: 0, bestScore: 0, gamesPlayed: 0 },
      recent: recentRows || []
    });
  } catch (err) {
    return res.status(500).json({ message: "Failed to load my score board", detail: err.message });
  }
});

app.post("/analyze", async (req, res) => {
  try {
    const url = String(req.body?.url || "").trim();
    if (!url) {
      return res.status(400).json({ message: "URL is required." });
    }

    const result = await autoAnalyze(url);
    return res.json(result);
  } catch (err) {
    return res.status(500).json({
      message: "Analyze failed",
      detail: String(err?.message || err || "Unknown error")
    });
  }
});

const PORT = process.env.PORT || 2906;

ensureDatabaseExists()
  .then(() => Promise.all([
    ensureUsersTable(),
    ensureLoginAuditTable(),
    ensureAnalyzerLogFile(),
    ensureAgentCaseFile(),
    ensureGameScoresTable(),
    ensureAnalysisHistoryTable(),
    ensureLeaderboardTable()
  ]))
  .then(() => backfillLeaderboardFromGameScores())
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error("Startup failed:", err.code || "UNKNOWN", err.message || "");
    process.exit(1);
  });


