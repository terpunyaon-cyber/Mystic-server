const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const BOT_SECRET = process.env.BOT_SECRET || "rainx-bot-secret";
const SIGN_SECRET = process.env.SIGN_SECRET || "rainx-sign-secret-xyz";
const DATA_FILE = path.join(__dirname, "data.json");

// ====== IN-MEMORY CACHE ======
let _keys = {};
let _config = {};
let _dirty = false;

function loadData() {
    try {
        if (!fs.existsSync(DATA_FILE)) {
            fs.writeFileSync(DATA_FILE, JSON.stringify({ keys: {}, config: {} }));
        }
        const d = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
        _keys = d.keys || {};
        _config = d.config || {};
    } catch {
        _keys = {};
        _config = {};
    }
}

function saveData() {
    _dirty = false;
    fs.writeFileSync(DATA_FILE, JSON.stringify({ keys: _keys, config: _config }, null, 2));
}

// auto-save ทุก 5 วิ ถ้ามีการเปลี่ยนแปลง
setInterval(() => { if (_dirty) saveData(); }, 5000);

// โหลดตอนเริ่ม
loadData();

// index userId -> key สำหรับ lookup เร็ว
const userIndex = new Map();
for (const [k, v] of Object.entries(_keys)) {
    if (v.usedBy) userIndex.set(v.usedBy, k);
}

// ====== STORES ======
const sessions = new Map();
const usedSessions = new Set();
const rateLimitMap = new Map();
const activeTokens = new Map();
const scriptTokens = new Map(); // one-time script tokens: token -> { userId, key, expireAt }

setInterval(() => {
    const now = Date.now();
    for (const [id, val] of sessions.entries()) {
        if (now > val.expireAt) sessions.delete(id);
    }
    for (const [hwid, val] of rateLimitMap.entries()) {
        if (now > val.resetAt) rateLimitMap.delete(hwid);
    }
    for (const [hwid, val] of activeTokens.entries()) {
        if (now > val.expireAt) activeTokens.delete(hwid);
    }
}, 30000);

// ====== HELPERS ======
function nowSec() { return Math.floor(Date.now() / 1000); }

function isExpired(k) {
    if (k.duration === -1) return false;
    if (k.expired) return true;
    if (!k.redeemedAt || k.redeemedAt === 0) return false;
    return nowSec() >= (k.redeemedAt + k.duration);
}

function encrypt(data, keyHex) {
    const key = Buffer.from(keyHex.slice(0, 64), "hex");
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    const json = JSON.stringify(data);
    let enc = cipher.update(json, "utf8", "base64");
    enc += cipher.final("base64");
    const tag = cipher.getAuthTag().toString("base64");
    return { d: enc, iv: iv.toString("base64"), t: tag };
}

function checkRate(hwid) {
    const now = Date.now();
    const e = rateLimitMap.get(hwid) || { count: 0, resetAt: now + 60000 };
    if (now > e.resetAt) { e.count = 0; e.resetAt = now + 60000; }
    e.count++;
    rateLimitMap.set(hwid, e);
    return e.count <= 8;
}

function botAuth(req, res, next) {
    if (req.headers["x-bot-secret"] !== BOT_SECRET)
        return res.status(403).json({ error: "forbidden" });
    next();
}

function guard(req, res, next) {
    const { hwid } = req.body;
    if (!hwid) return res.json({ e: "bad" });
    if (!checkRate(hwid)) return res.json({ e: "rate" });
    next();
}

// ====== FAKE ENDPOINTS ======
app.post("/api/v1/auth", (req, res) => {
    res.json({ ok: true, token: crypto.randomBytes(32).toString("base64"), expires: nowSec() + 300 });
});
app.post("/api/v2/verify", (req, res) => {
    res.json({ ok: true, authorized: true });
});
app.post("/api/v3/check", (req, res) => {
    res.json({ d: crypto.randomBytes(64).toString("base64"), iv: crypto.randomBytes(12).toString("base64"), t: crypto.randomBytes(16).toString("base64"), ok: true });
});

// ====== REAL ENDPOINTS ======
app.post("/cdn-cgi/challenge", guard, (req, res) => {
    const { key, hwid, ts, nonce, fp } = req.body;
    if (!key || !hwid || !ts || !nonce || !fp) return res.json({ e: "bad" });
    if (Math.abs(nowSec() - ts) > 10) return res.json({ e: "ts" });
    if (!/^[a-f0-9]{32}$/.test(nonce)) return res.json({ e: "bad" });
    if (fp.length < 32) return res.json({ e: "bad" });

    const keyData = _keys[key];
    if (!keyData) return res.json({ e: "key" });
    if (isExpired(keyData)) {
        keyData.expired = true;
        _dirty = true;
        return res.json({ e: "exp" });
    }

    const sessionId = crypto.randomBytes(16).toString("hex");
    const sessionKey = crypto.randomBytes(32).toString("hex");

    const clientIp = req.headers["x-forwarded-for"]?.split(",")[0].trim() || req.ip;
    const hashedHwidChallenge = crypto.createHash("sha256").update(hwid).digest("hex");

    sessions.set(sessionId, {
        sessionKey, key,
        hwid: hashedHwidChallenge, // เก็บ hashed ไม่เก็บ raw
        nonce, fp,
        ip: clientIp,
        expireAt: Date.now() + 15000
    });

    res.json({ s: sessionId, k: sessionKey });
});

app.post("/cdn-cgi/token", guard, (req, res) => {
    const { s, hwid, ts, nonce, fp } = req.body;
    if (!s || !hwid || !ts || !nonce || !fp) return res.json({ e: "bad" });
    if (Math.abs(nowSec() - ts) > 10) return res.json({ e: "ts" });
    if (usedSessions.has(s)) return res.json({ e: "used" });

    const entry = sessions.get(s);
    if (!entry) return res.json({ e: "sess" });

    const reqIp = req.headers["x-forwarded-for"]?.split(",")[0].trim() || req.ip;
    const hashedHwidToken = crypto.createHash("sha256").update(hwid).digest("hex");

    // เช็ค IP ต้องตรงกับตอน challenge + hwid hashed ต้องตรง
    if (entry.hwid !== hashedHwidToken || entry.nonce !== nonce || entry.fp !== fp || entry.ip !== reqIp)
        return res.json({ e: "bad" });

    usedSessions.add(s);
    sessions.delete(s);
    setTimeout(() => usedSessions.delete(s), 30000);

    const keyData = _keys[entry.key];
    if (!keyData) return res.json({ e: "key" });
    if (isExpired(keyData)) {
        keyData.expired = true;
        _dirty = true;
        return res.json({ e: "exp" });
    }

    // ใช้ hashedHwidToken ที่คำนวณไว้แล้วด้านบน ไม่ต้อง hash ซ้ำ
    if (keyData.hwid && keyData.hwid !== "" && keyData.hwid !== hashedHwidToken)
        return res.json({ e: "hwid" });

    if (!keyData.hwid || keyData.hwid === "") keyData.hwid = hashedHwidToken;
    if (!keyData.redeemedAt || keyData.redeemedAt === 0) keyData.redeemedAt = nowSec();
    keyData.active = true;
    keyData.expired = false;
    keyData.executionCount = (keyData.executionCount || 0) + 1;
    _dirty = true;

    const activeToken = crypto.randomBytes(32).toString("hex");
    activeTokens.set(hashedHwidToken, {
        token: activeToken,
        key: entry.key,
        expireAt: Date.now() + 5 * 60 * 1000
    });

    // สร้าง one-time script token
    const scriptToken = crypto.randomBytes(32).toString("hex");
    scriptTokens.set(scriptToken, {
        userId: keyData.usedBy,
        key: entry.key,
        expireAt: Date.now() + 60000 // หมดใน 60 วิ
    });

    const payload = {
        ok: true,
        scriptToken, // ใช้แทน scriptUrl โดยตรง
        activeToken,
        ts: nowSec()
    };

    res.json(encrypt(payload, entry.sessionKey));
});

app.post("/cdn-cgi/heartbeat", guard, (req, res) => {
    const { hwid, token, ts } = req.body;
    if (!hwid || !token || !ts) return res.json({ alive: false });
    if (Math.abs(nowSec() - ts) > 15) return res.json({ alive: false });
    const hashedHwid = crypto.createHash("sha256").update(hwid).digest("hex");
    const entry = activeTokens.get(hashedHwid);
    if (!entry || entry.token !== token || Date.now() > entry.expireAt)
        return res.json({ alive: false });
    entry.expireAt = Date.now() + 5 * 60 * 1000;
    res.json({ alive: true });
});

// ====== BOT ENDPOINTS ======
app.post("/keys/generate", botAuth, (req, res) => {
    const { duration, amount } = req.body;
    const keys = [];
    for (let i = 0; i < Math.min(amount || 1, 50); i++) {
        const key = crypto.randomBytes(16).toString("hex");
        _keys[key] = {
            active: false, expired: false, duration: duration ?? -1,
            executionCount: 0, hwid: "", createdAt: nowSec(), redeemedAt: 0, lastHwidReset: 0
        };
        keys.push(key);
    }
    _dirty = true;
    res.json({ ok: true, keys });
});

app.delete("/keys/:key", botAuth, (req, res) => {
    if (!_keys[req.params.key]) return res.status(404).json({ ok: false });
    const kd = _keys[req.params.key];
    if (kd.usedBy) userIndex.delete(kd.usedBy);
    delete _keys[req.params.key];
    _dirty = true;
    res.json({ ok: true });
});

app.get("/keys/:key", botAuth, (req, res) => {
    const kd = _keys[req.params.key];
    if (!kd) return res.status(404).json({ ok: false });
    res.json({ ok: true, key: req.params.key, data: kd });
});

app.get("/keys", botAuth, (req, res) => {
    res.json({ ok: true, keys: _keys });
});

app.post("/keys/:key/reset-hwid", botAuth, (req, res) => {
    const kd = _keys[req.params.key];
    if (!kd) return res.status(404).json({ ok: false });
    kd.hwid = "";
    kd.lastHwidReset = nowSec();
    _dirty = true;
    res.json({ ok: true });
});

// lookup เร็วด้วย userIndex
app.get("/keys/user/:userId", botAuth, (req, res) => {
    const key = userIndex.get(req.params.userId);
    if (!key || !_keys[key]) return res.status(404).json({ ok: false });
    res.json({ ok: true, key, data: _keys[key] });
});

app.post("/keys/:key/redeem", botAuth, (req, res) => {
    const { userId } = req.body;
    const kd = _keys[req.params.key];
    if (!kd) return res.status(404).json({ ok: false, reason: "Key ไม่ถูกต้อง" });
    if (isExpired(kd)) {
        kd.expired = true; _dirty = true;
        return res.json({ ok: false, reason: "Key หมดอายุแล้ว" });
    }
    if (kd.usedBy && kd.usedBy !== "" && kd.usedBy !== userId)
        return res.json({ ok: false, reason: "Key used by someone else" });
    if (kd.usedBy === userId)
        return res.json({ ok: false, reason: "Already redeemed" });
    kd.usedBy = userId;
    kd.active = true;
    if (!kd.redeemedAt || kd.redeemedAt === 0) kd.redeemedAt = nowSec();
    userIndex.set(userId, req.params.key);
    _dirty = true;
    res.json({ ok: true, duration: kd.duration });
});

app.post("/config", botAuth, (req, res) => {
    _config = { ..._config, ...req.body };
    _dirty = true;
    res.json({ ok: true });
});

app.get("/config", botAuth, (req, res) => {
    res.json({ ok: true, config: _config });
});

// one-time script endpoint
app.get("/cdn-cgi/resource", (req, res) => {
    const { t } = req.query;
    if (!t) return res.status(403).send("forbidden");

    const entry = scriptTokens.get(t);
    if (!entry) return res.status(403).send("forbidden");
    if (Date.now() > entry.expireAt) {
        scriptTokens.delete(t);
        return res.status(403).send("expired");
    }

    // ใช้แล้วลบทันที one-time only
    scriptTokens.delete(t);

    const scriptUrl = _config.scriptUrl;
    if (!scriptUrl) return res.status(404).send("no script");

    // ฝัง watermark - ถ้าเอาไปแจกรู้ทันทีว่าใคร
    const watermark = `-- [RainX] Licensed to: ${entry.userId} | Key: ${entry.key.slice(0,8)}...
-- Redistribution is prohibited.
getgenv().key = "${entry.key}"
getgenv()._owner = "${entry.userId}"
loadstring(game:HttpGet("${scriptUrl}"))()`;

    res.setHeader("Content-Type", "text/plain");
    res.send(watermark);
});

app.get("/ping", (req, res) => res.send("pong"));
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
