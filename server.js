// UCell server.js (stabilized)
require("dotenv").config({ override: true });

const express = require("express");
const fs = require("fs");
const path = require("path");
const multer = require("multer");
const crypto = require("crypto");
const session = require("express-session");
const { Pool } = require("pg");
console.log("OPENAI_API_KEY present:", !!process.env.OPENAI_API_KEY);
const app = express();
// ---- Core middleware (order matters) ----
app.set("trust proxy", 1);

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: false }));

app.use(
  session({
    name: "ucell.sid",
    secret: process.env.SESSION_SECRET || "ucell-permanent-session-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
    },
  })
);

const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);
app.use("/uploads", express.static(UPLOAD_DIR));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

pool.on("error", (err) => {
  console.error("Postgres pool error (connection was terminated):");
  console.error(err && err.stack ? err.stack : err);
});

async function initDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS logs (
        id SERIAL PRIMARY KEY,
        ts TIMESTAMP NOT NULL,
        username VARCHAR(255) NOT NULL,
        role VARCHAR(50) NOT NULL,
        text TEXT,
        file_name VARCHAR(500),
        file_original VARCHAR(500),
        file_type VARCHAR(50),
        ai_analysis JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS users (
        username VARCHAR(255) PRIMARY KEY,
        password VARCHAR(255) NOT NULL,
        is_admin BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_logs_username ON logs(username);
      CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts DESC);
    `);
    console.log("Database tables initialized");
  } catch (err) {
    console.error("Database initialization error:", err);
  }
}

function hashPassword(password) {
  return crypto.createHash("sha256").update(String(password)).digest("hex");
}

async function initializeUsers() {
  try {
    const result = await pool.query("SELECT COUNT(*) FROM users");
    if (parseInt(result.rows[0].count, 10) === 0) {
      await pool.query(
        "INSERT INTO users (username, password, is_admin) VALUES ($1, $2, $3)",
        ["james", hashPassword("ucell2024"), true]
      );
      console.log("Created default admin user: james / ucell2024");
    }
  } catch (err) {
    console.error("User initialization error:", err);
  }
}

initDatabase().then(initializeUsers);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname),
});
const upload = multer({ storage });
function requireAuth(req, res, next) {
  if (!req.session || !req.session.user) {
    const wantsHtml = req.method === "GET" && (req.headers.accept || "").includes("text/html");
    if (wantsHtml) return res.redirect("/login");
    return res.status(401).json({ error: "Not authenticated" });
  }
  req.user = req.session.user.username;
  req.isAdmin = !!req.session.user.isAdmin;
  return next();
}

function requireAdmin(req, res, next) {
  if (!req.session || !req.session.user) {
    const wantsHtml = req.method === "GET" && (req.headers.accept || "").includes("text/html");
    if (wantsHtml) return res.redirect("/login");
    return res.status(401).json({ error: "Not authenticated" });
  }
  if (!req.session.user.isAdmin) {
    return res.status(403).json({ error: "Admin access required" });
  }
  return next();
}

app.get("/", (req, res) => {
  if (req.session && req.session.user) return res.redirect("/terminal");
  return res.redirect("/login");
});

app.get("/login", (req, res) => {
  res.type("html").send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>UCell Login</title>
  <style>
    html, body { height:100%; margin:0; background:#050607; color:#c8ffd7; font-family: ui-monospace, Menlo, Consolas, monospace; }
    .wrap { height:100%; display:flex; align-items:center; justify-content:center; padding:24px; box-sizing:border-box; }
    .card { width:100%; max-width:420px; border:1px solid rgba(200,255,215,0.14); border-radius:12px; padding:18px; background:rgba(200,255,215,0.03); }
    .title { letter-spacing:2px; text-transform:uppercase; font-size:12px; color:rgba(200,255,215,0.55); margin-bottom:10px; }
    label { display:block; font-size:12px; color:rgba(200,255,215,0.55); margin-top:12px; }
    input { width:100%; margin-top:6px; padding:10px 12px; box-sizing:border-box; border-radius:10px; border:1px solid rgba(200,255,215,0.18); background:#07090a; color:#c8ffd7; outline:none; }
    button { margin-top:16px; width:100%; padding:10px 12px; border-radius:10px; border:1px solid rgba(200,255,215,0.22); background:rgba(200,255,215,0.06); color:#c8ffd7; cursor:pointer; }
    .hint { margin-top:12px; font-size:11px; color:rgba(200,255,215,0.35); line-height:1.4; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="title">UCell Access</div>
      <form method="POST" action="/login">
        <label>Username</label>
        <input name="username" autocomplete="username" />
        <label>Password</label>
        <input name="password" type="password" autocomplete="current-password" />
        <button type="submit">Enter</button>
      </form>
      <div class="hint">This establishes a session cookie in your browser, then redirects to <code>/terminal</code>.</div>
    </div>
  </div>
</body>
</html>`);
});

app.post("/login", async (req, res) => {
  const username = String(req.body?.username || "").trim();
  const password = String(req.body?.password || "");
  if (!username || !password) {
    return res.status(400).type("text/plain").send("Missing username or password");
  }
  try {
    const result = await pool.query("SELECT username, password, is_admin FROM users WHERE username = $1", [username]);
    if (result.rows.length === 0) {
      return res.status(401).type("text/plain").send("Invalid credentials");
    }
    const row = result.rows[0];
    if (row.password !== hashPassword(password)) {
      return res.status(401).type("text/plain").send("Invalid credentials");
    }
    req.session.user = { username: row.username, isAdmin: !!row.is_admin };
    return res.redirect("/terminal");
  } catch (e) {
    console.error("POST /login error:", e);
    return res.status(500).type("text/plain").send("Login failed");
  }
});

app.post("/logout", (req, res) => {
  try {
    req.session.destroy(() => res.redirect("/login"));
  } catch (_) {
    res.redirect("/login");
  }
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }
  try {
    const result = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
    if (result.rows.length === 0 || result.rows[0].password !== hashPassword(password)) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    req.session.user = { username, isAdmin: result.rows[0].is_admin || false };
    res.json({ ok: true, username, isAdmin: req.session.user.isAdmin });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

app.post("/api/logout", requireAuth, async (req, res) => {
  try {
    req.session.destroy(() => res.json({ ok: true }));
  } catch (err) {
    console.error("Logout error:", err);
    res.status(500).json({ error: "Logout failed" });
  }
});

app.get("/api/me", requireAuth, async (req, res) => {
  try {
    const result = await pool.query("SELECT is_admin FROM users WHERE username = $1", [req.user]);
    res.json({ username: req.user, isAdmin: result.rows[0]?.is_admin || false });
  } catch (err) {
    console.error("Me error:", err);
    res.status(500).json({ error: "Failed to get user info" });
  }
});
app.post("/api/summary", requireAuth, requireAdmin, async (req, res) => {
  const range = req.body && typeof req.body.range === "string" ? req.body.range : "week";
  const username = req.user;

  function startOfDay(d) {
    const x = new Date(d);
    x.setHours(0, 0, 0, 0);
    return x;
  }

  function endOfDay(d) {
    const x = new Date(d);
    x.setHours(23, 59, 59, 999);
    return x;
  }

  function rangeBounds(r) {
    const now = new Date();
    const end = endOfDay(now);
    const start = new Date(end);
    if (r === "week") {
      start.setDate(start.getDate() - 6);
      return { start: startOfDay(start), end, label: "Last 7 days" };
    }
    if (r === "month") {
      start.setDate(start.getDate() - 29);
      return { start: startOfDay(start), end, label: "Last 30 days" };
    }
    if (r === "quarter") {
      start.setDate(start.getDate() - 89);
      return { start: startOfDay(start), end, label: "Last 90 days" };
    }
    if (r === "year") {
      start.setDate(start.getDate() - 364);
      return { start: startOfDay(start), end, label: "Last 365 days" };
    }
    start.setDate(start.getDate() - 6);
    return { start: startOfDay(start), end, label: "Last 7 days" };
  }

  function prevBounds(currStart, currEnd, currLabel) {
    const durationMs = currEnd.getTime() - currStart.getTime();
    const prevEnd = new Date(currStart.getTime() - 1);
    const prevStart = new Date(prevEnd.getTime() - durationMs);
    return { start: startOfDay(prevStart), end: endOfDay(prevEnd), label: "Prior period (" + currLabel + ")" };
  }

  function safeParseLogText(s) {
    try {
      const obj = JSON.parse(s);
      if (obj && typeof obj === "object") {
        const type = typeof obj.type === "string" ? obj.type : "note";
        const text = typeof obj.text === "string" ? obj.text : typeof obj.raw === "string" ? obj.raw : "";
        const bristol = Number.isInteger(obj.bristol) ? obj.bristol : null;
        return { type, text, bristol, raw: obj.raw || text };
      }
    } catch (_) {}
    return { type: "note", text: String(s || ""), bristol: null, raw: String(s || "") };
  }

  function clampPct(n) {
    if (!Number.isFinite(n)) return null;
    return Math.max(0, Math.min(100, Math.round(n)));
  }

  function minutesBetween(a, b) {
    return Math.round((b.getTime() - a.getTime()) / 60000);
  }

  function normalizeText(t) {
    return String(t || "").toLowerCase();
  }

  function daysInWindow(win) {
    const ms = win.end.getTime() - win.start.getTime();
    const days = Math.floor(ms / (24 * 60 * 60 * 1000)) + 1;
    return Math.max(1, days);
  }

  function safePct(numer, denom) {
    if (!Number.isFinite(numer) || !Number.isFinite(denom) || denom <= 0) return null;
    return clampPct((numer / denom) * 100);
  }

  const TRIGGERS = [
    { key: "high_fat", label: "High-fat", re: /\b(high\s*fat|fatty|fried|greasy|butter|cream|cheese|bacon|sausage|burger|pizza)\b/i },
    { key: "dairy", label: "Dairy", re: /\b(dairy|milk|cheese|cream|ice\s*cream|yogurt|whey|casein)\b/i },
    { key: "spicy", label: "Spicy", re: /\b(spicy|hot\s*sauce|chili|pepper|jalapeno|sriracha)\b/i },
    { key: "alcohol", label: "Alcohol", re: /\b(alcohol|beer|wine|vodka|whiskey|tequila|cocktail)\b/i },
    { key: "caffeine", label: "Caffeine", re: /\b(caffeine|coffee|espresso|latte|energy\s*drink|celsius|monster)\b/i },
    { key: "high_fiber", label: "High-fiber", re: /\b(high\s*fiber|fiber|beans|lentils|bran|raw\s*veg|salad)\b/i },
    { key: "late_meal", label: "Late meal", re: /\b(late\s*night|midnight|after\s*10|after\s*11|after\s*12)\b/i },
    { key: "gluten", label: "Gluten", re: /\b(gluten|bread|pasta|wheat|flour)\b/i },
    { key: "sugar", label: "High-sugar", re: /\b(sugar|dessert|candy|cake|cookies|ice\s*cream|soda)\b/i }
  ];

  const SYMPTOM_TERMS = [
    { key: "cramps", label: "Cramps", re: /\b(cramp|cramps)\b/i },
    { key: "urgency", label: "Urgency", re: /\b(urgency|urgent)\b/i },
    { key: "bloating", label: "Bloating", re: /\b(bloat|bloating)\b/i },
    { key: "pain", label: "Pain", re: /\b(pain|ache)\b/i },
    { key: "nausea", label: "Nausea", re: /\b(nausea|nauseous)\b/i },
    { key: "reflux", label: "Reflux", re: /\b(reflux|heartburn|gerd)\b/i },
    { key: "blood", label: "Blood", re: /\b(blood|bleeding)\b/i },
    { key: "mucus", label: "Mucus", re: /\b(mucus)\b/i }
  ];

  function confidenceLabel(entryCount, stoolCount) {
    if (entryCount >= 40 && stoolCount >= 7) return "High";
    if (entryCount >= 15 && stoolCount >= 3) return "Medium";
    return "Low";
  }

  function fmtDelta(n) {
    if (n === null || n === undefined || !Number.isFinite(n)) return "–";
    if (n > 0) return "+" + n;
    return "" + n;
  }

  function fmtPctDelta(curr, prev) {
    if (!Number.isFinite(curr) || !Number.isFinite(prev)) return "–";
    const d = curr - prev;
    if (d > 0) return "+" + d + "%";
    return d + "%";
  }

  try {
    const curr = rangeBounds(range);
    const prev = prevBounds(curr.start, curr.end, curr.label);

    async function computeForWindow(win) {
      const q = await pool.query(
        "SELECT ts, role, text, ai_analysis FROM logs WHERE username = $1 AND ts >= $2 AND ts <= $3 ORDER BY ts ASC",
        [username, win.start, win.end]
      );
      const rows = q.rows || [];
      const userRows = rows;
      const totals = {
        entries: userRows.length,
        byType: { meal: 0, beverage: 0, stool: 0, symptom: 0, mood: 0, sleep: 0, note: 0 }
      };
      const stool = {
        total: 0,
        bristolCounts: { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0, 6: 0, 7: 0 },
        normalCount: 0,
        diarrheaCount: 0,
        constipationCount: 0
      };
      const triggers = {};
      TRIGGERS.forEach((t) => (triggers[t.key] = 0));
      const symptomHits = {};
      SYMPTOM_TERMS.forEach((s) => (symptomHits[s.key] = 0));
      const mealEvents = [];
      const stoolEvents = [];

      for (const r of userRows) {
  const parsed = safeParseLogText(r.text);
  const type = (parsed.type || "note").toLowerCase();
  const txt = String(parsed.text || "");
  normalizeText(txt);

  // Check ai_analysis for stool photos
  let ai = r.ai_analysis;
  if (typeof ai === "string") {
    try { ai = JSON.parse(ai); } catch (_) { ai = null; }
  }
  const aiKind = ai && typeof ai.kind === "string" ? ai.kind : "";
  const aiStatus = ai && typeof ai.status === "string" ? ai.status : "";
  const aiBristol = ai && Number.isInteger(ai.bristol) ? ai.bristol : null;

  // If it's a stool photo with Bristol score, count it as stool
  if (ai && aiStatus === "ok" && aiKind === "stool_photo_bristol" && aiBristol != null && aiBristol >= 1 && aiBristol <= 7) {
    totals.byType.stool += 1;
    stool.total += 1;
    stool.bristolCounts[aiBristol] += 1;
    if (aiBristol === 3 || aiBristol === 4) stool.normalCount += 1;
    if (aiBristol === 6 || aiBristol === 7) stool.diarrheaCount += 1;
    if (aiBristol === 1 || aiBristol === 2) stool.constipationCount += 1;
    stoolEvents.push({ ts: new Date(r.ts), bristol: aiBristol });
  } else {
    // Normal text-based logging
    if (totals.byType[type] == null) totals.byType.note += 1;
    else totals.byType[type] += 1;

    if (type === "meal" || type === "beverage") {
      const hitKeys = [];
      
      // Check text-based triggers
      for (const trig of TRIGGERS) {
        if (trig.re.test(txt)) hitKeys.push(trig.key);
      }
      
      // Check meal photo AI analysis for detected triggers
      if (ai && aiKind === "meal_photo_macros" && aiStatus === "ok" && Array.isArray(ai.detected_triggers)) {
        for (const detected of ai.detected_triggers) {
          if (!hitKeys.includes(detected)) {
            hitKeys.push(detected);
          }
        }
      }
      
      // Build meal description for correlation details
      let mealText = txt;
      if (ai && aiKind === "meal_photo_macros" && aiStatus === "ok") {
        const desc = ai.meal_description || "";
        const trigDetail = ai.trigger_details || "";
        if (desc) mealText = desc + (trigDetail ? " (" + trigDetail + ")" : "");
      }
      
      mealEvents.push({ ts: new Date(r.ts), text: mealText, triggerKeys: hitKeys });
    }

    if (type === "stool") {
      stool.total += 1;
      const b = parsed.bristol;
      if (Number.isInteger(b) && b >= 1 && b <= 7) {
        stool.bristolCounts[b] += 1;
        if (b === 3 || b === 4) stool.normalCount += 1;
        if (b === 6 || b === 7) stool.diarrheaCount += 1;
        if (b === 1 || b === 2) stool.constipationCount += 1;
        stoolEvents.push({ ts: new Date(r.ts), bristol: b });
      }
    }

    if (type === "symptom") {
      for (const s of SYMPTOM_TERMS) {
        if (s.re.test(txt)) symptomHits[s.key] += 1;
      }
    }
  }
}

      const diarrheaEvents = stoolEvents.filter((s) => s.bristol === 6 || s.bristol === 7);
      const correlationWindowMs = 24 * 60 * 60 * 1000;
      const correlations = [];
      for (const s of diarrheaEvents) {
        const sTime = s.ts.getTime();
        const windowStart = sTime - correlationWindowMs;
        const candidates = mealEvents.filter((m) => {
          const mt = m.ts.getTime();
          return mt >= windowStart && mt <= sTime;
        });
        const matched = [];
        for (const m of candidates) {
          for (const k of m.triggerKeys) {
            matched.push({
              key: k,
              label: TRIGGERS.find((t) => t.key === k)?.label || k,
              mealText: m.text,
              minutesAgo: minutesBetween(m.ts, s.ts)
            });
            triggers[k] += 1;
          }
        }
        correlations.push({
          stoolTs: s.ts,
          bristol: s.bristol,
          matchedTriggers: matched.sort((a, b) => a.minutesAgo - b.minutesAgo).slice(0, 5)
        });
      }
      const topTriggers = Object.entries(triggers).filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([k, v]) => ({
        key: k,
        label: TRIGGERS.find((t) => t.key === k)?.label || k,
        count: v
      }));
      const stoolNormalPct = stool.total > 0 ? clampPct((stool.normalCount / stool.total) * 100) : null;
      const confidence = confidenceLabel(totals.entries, stool.total);
      return { window: win, totals, stool, stoolNormalPct, correlations, topTriggers, symptomHits, confidence, triggers };
    }

    const currR = await computeForWindow(curr);
    const lines = [];
    const prevR = await computeForWindow(prev);

    const deltaEntries = currR.totals.entries - prevR.totals.entries;
    const deltaSymptoms = currR.totals.byType.symptom - prevR.totals.byType.symptom;
    const deltaStool = currR.totals.byType.stool - prevR.totals.byType.stool;
    const deltaDiarrhea = currR.stool.diarrheaCount - prevR.stool.diarrheaCount;
    const currNormal = currR.stoolNormalPct;
    const prevNormal = prevR.stoolNormalPct;

    const flags = [];
    function addFlag(key, level, title, rationale, evidence) {
      flags.push({ key, level, title, rationale, evidence });
    }

    const currDays = daysInWindow(currR.window);
    const prevDays = daysInWindow(prevR.window);
    const currDiarrheaPer7 = Math.round((currR.stool.diarrheaCount / currDays) * 7 * 10) / 10;
    const prevDiarrheaPer7 = Math.round((prevR.stool.diarrheaCount / prevDays) * 7 * 10) / 10;
    const currNormalPctSafe = Number.isFinite(currNormal) ? currNormal : null;
    const prevNormalPctSafe = Number.isFinite(prevNormal) ? prevNormal : null;
    const normalPctDrop = currNormalPctSafe != null && prevNormalPctSafe != null ? currNormalPctSafe - prevNormalPctSafe : null;
    const bloodHits = (currR.symptomHits && currR.symptomHits.blood) ? currR.symptomHits.blood : 0;
    const totalTriggerHits = Object.values(currR.triggers || {}).reduce((a, b) => a + (Number.isFinite(b) ? b : 0), 0);
    const topTrig = (currR.topTriggers && currR.topTriggers.length) ? currR.topTriggers[0] : null;
    const topTrigShare = topTrig && totalTriggerHits > 0 ? topTrig.count / totalTriggerHits : null;

    if (currR.confidence === "Low") {
      addFlag("low_confidence", "info", "Low data confidence", "The report is based on limited entries or limited stool coverage, so trends and correlations may be unstable.", "Entries: " + currR.totals.entries + ", stool entries: " + currR.totals.byType.stool + ", confidence: " + currR.confidence);
    }
    if (bloodHits > 0) {
      addFlag("blood_reported", "red", "Blood mentioned in symptom logs", "Blood is a high-salience symptom signal and should be reviewed promptly in context.", "Blood mentions: " + bloodHits + " (range: " + currR.window.label + ")");
    }
    if (currR.stool.diarrheaCount >= 3 || currDiarrheaPer7 >= 3) {
      addFlag("sustained_diarrhea", "amber", "Sustained diarrhea-range stools", "Multiple Bristol 6–7 events were logged in the current window, suggesting reduced stool quality stability.", "Bristol 6–7: " + currR.stool.diarrheaCount + " over " + currDays + " day(s) (~" + currDiarrheaPer7 + "/7d)");
    }
    if (deltaDiarrhea >= 2) {
      addFlag("worsening_diarrhea_vs_prior", "amber", "Worsening diarrhea vs prior period", "The current window shows a meaningful increase in Bristol 6–7 events versus the immediately preceding equivalent period.", "Current: " + currR.stool.diarrheaCount + " (~" + currDiarrheaPer7 + "/7d), Prior: " + prevR.stool.diarrheaCount + " (~" + prevDiarrheaPer7 + "/7d), Delta: " + fmtDelta(deltaDiarrhea));
    }
    if (currNormalPctSafe != null && currR.stool.total >= 3 && currNormalPctSafe <= 40) {
      addFlag("low_normal_pct", "amber", "Low proportion of normal stools", "A minority of logged stools were Bristol 3–4, indicating reduced baseline stability in the current window.", "Normal (3–4): " + currNormalPctSafe + "% of " + currR.stool.total + " stool entries");
    }
    if (normalPctDrop != null && normalPctDrop <= -15) {
      addFlag("normal_pct_drop_vs_prior", "amber", "Normal stool percentage dropped vs prior period", "The proportion of Bristol 3–4 stools decreased meaningfully versus the prior equivalent window.", "Current: " + currNormalPctSafe + "%, Prior: " + prevNormalPctSafe + "%, Change: " + fmtPctDelta(currNormalPctSafe, prevNormalPctSafe));
    }
    if (topTrig && totalTriggerHits >= 3 && topTrigShare != null && topTrigShare >= 0.5) {
      addFlag("trigger_concentration", "info", "Trigger signal is concentrated", "A single trigger category accounts for at least half of detected trigger hits within the 24h lookback correlations, which may guide a structured trial.", "Top trigger: " + topTrig.label + " (" + topTrig.count + "/" + totalTriggerHits + ", " + Math.round(topTrigShare * 100) + "%)");
    }

    lines.push("0) Key clinical flags");
    if (!flags.length) {
      lines.push("No deterministic flags triggered in this range based on available logs.");
    } else {
      for (const f of flags) {
        const lvl = (f.level || "info").toUpperCase();
        lines.push("- " + lvl + ": " + f.title + ". " + f.rationale + " Evidence: " + f.evidence);
      }
    }
    lines.push("");
    lines.push("1) Comparison vs prior period");
    lines.push("Prior period: " + prevR.window.label);
    lines.push("Entries: " + currR.totals.entries + " (" + fmtDelta(deltaEntries) + ")");
    lines.push("Stool entries: " + currR.totals.byType.stool + " (" + fmtDelta(deltaStool) + ")");
    lines.push("Symptom entries: " + currR.totals.byType.symptom + " (" + fmtDelta(deltaSymptoms) + ")");
    lines.push("Bristol 6–7 events: " + currR.stool.diarrheaCount + " (" + fmtDelta(deltaDiarrhea) + ")");
    if (currNormal != null && prevNormal != null) {
      lines.push("Normal stool % (Bristol 3–4): " + currNormal + "% (" + fmtPctDelta(currNormal, prevNormal) + " vs prior)");
    } else {
      lines.push("Normal stool % (Bristol 3–4): – (insufficient stool data in one or both periods)");
    }
    lines.push("");
    lines.push("2) Summary");
    lines.push("Entries: " + currR.totals.entries + ". Meals: " + currR.totals.byType.meal + ", Stool: " + currR.totals.byType.stool + ", Symptoms: " + currR.totals.byType.symptom + ", Sleep: " + currR.totals.byType.sleep + ", Mood: " + currR.totals.byType.mood + ", Notes: " + currR.totals.byType.note + ".");
    lines.push("");
    lines.push("3) Stool quality");
    if (currR.stool.total === 0) {
      lines.push("No stool entries recorded in this range.");
    } else {
      lines.push("Stool entries: " + currR.stool.total + ". Normal (Bristol 3–4): " + (currR.stoolNormalPct != null ? currR.stoolNormalPct + "%" : "–") + ".");
      lines.push("Diarrhea-range (Bristol 6–7): " + currR.stool.diarrheaCount + ". Constipation-range (Bristol 1–2): " + currR.stool.constipationCount + ".");
      lines.push("Bristol distribution: 1:" + currR.stool.bristolCounts[1] + " 2:" + currR.stool.bristolCounts[2] + " 3:" + currR.stool.bristolCounts[3] + " 4:" + currR.stool.bristolCounts[4] + " 5:" + currR.stool.bristolCounts[5] + " 6:" + currR.stool.bristolCounts[6] + " 7:" + currR.stool.bristolCounts[7] + ".");
      lines.push("Diarrhea frequency estimate: ~" + currDiarrheaPer7 + "/7d (current), ~" + prevDiarrheaPer7 + "/7d (prior).");
    }
    lines.push("");
    lines.push("4) Trigger hypotheses (24h lookback for Bristol 6–7)");
    if (currR.stool.diarrheaCount === 0) {
      lines.push("No Bristol 6–7 events detected in this range.");
    } else if ((currR.topTriggers || []).length === 0) {
      lines.push("Bristol 6–7 events occurred, but no detectable trigger keywords were found in meal text.");
    } else {
      const top = currR.topTriggers.map((t) => t.label + " (" + t.count + ")").join(", ");
      lines.push("Most common correlated triggers: " + top + ".");
      lines.push("Bristol 6–7 occurred " + currR.stool.diarrheaCount + " time(s). Correlations were detected based on meal text within 24 hours.");
    }
    if (currR.stool.diarrheaCount > 0) {
      const maxDetails = 3;
      const detailed = (currR.correlations || []).filter((c) => c.bristol === 6 || c.bristol === 7).slice(-maxDetails);
      if (detailed.length > 0) {
        lines.push("");
        lines.push("Event detail (most recent):");
        for (const ev of detailed) {
          const when = ev.stoolTs.toLocaleString();
          if (!ev.matchedTriggers.length) {
            lines.push("- " + when + ": Bristol " + ev.bristol + ", no trigger keywords detected in preceding meal logs.");
          } else {
            const parts = ev.matchedTriggers.map((m) => m.label + " (" + m.minutesAgo + "m before): \"" + m.mealText + "\"");
            lines.push("- " + when + ": Bristol " + ev.bristol + ", possible triggers: " + parts.join(" | "));
          }
        }
      }
    }
    lines.push("");
    lines.push("5) Symptoms, sleep, mood");
    if (currR.totals.byType.symptom === 0) {
      lines.push("Symptoms: no symptom entries recorded.");
    } else {
      const topSym = Object.entries(currR.symptomHits || {}).filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1]).slice(0, 4).map(([k, v]) => (SYMPTOM_TERMS.find((s) => s.key === k)?.label || k) + " (" + v + ")");
      lines.push("Symptoms: " + currR.totals.byType.symptom + " entries." + (topSym.length ? " Common themes: " + topSym.join(", ") + "." : ""));
    }
    lines.push("Sleep: " + currR.totals.byType.sleep + " entries.");
    lines.push("Mood: " + currR.totals.byType.mood + " entries.");
    lines.push("");
    lines.push("6) Actionable hypotheses");
    if (currR.stool.diarrheaCount === 0) {
      lines.push("- No diarrhea-range events logged. Maintain current logging cadence to improve trend detection.");
    } else {
      if ((currR.topTriggers || []).length > 0) {
        lines.push("- If tolerated, trial reducing: " + currR.topTriggers.map((t) => t.label).join(", ") + " for 7–14 days, then re-check weekly report.");
      } else {
        lines.push("- Add meal detail (fat, dairy, spicy, alcohol, caffeine) to improve trigger detection for Bristol 6–7 events.");
      }
      lines.push("- Log stool entries with a Bristol score when possible, even on normal days, to improve baseline accuracy.");
    }

    res.json({
      ok: true,
      rangeLabel: currR.window.label,
      confidence: currR.confidence,
      flags: { count: flags.length, items: flags },
      comparison: {
        priorLabel: prevR.window.label,
        deltas: {
          entries: deltaEntries,
          stoolEntries: deltaStool,
          symptomEntries: deltaSymptoms,
          diarrheaEvents: deltaDiarrhea,
          normalPctDelta: Number.isFinite(currNormal) && Number.isFinite(prevNormal) ? currNormal - prevNormal : null
        },
        current: {
          entries: currR.totals.entries,
          stoolEntries: currR.totals.byType.stool,
          symptomEntries: currR.totals.byType.symptom,
          diarrheaEvents: currR.stool.diarrheaCount,
          stoolNormalPct: currNormal
        },
        prior: {
          entries: prevR.totals.entries,
          stoolEntries: prevR.totals.byType.stool,
          symptomEntries: prevR.totals.byType.symptom,
          diarrheaEvents: prevR.stool.diarrheaCount,
          stoolNormalPct: prevNormal
        }
      },
      metrics: {
        entries: currR.totals.entries,
        byType: currR.totals.byType,
        stoolTotal: currR.stool.total,
        stoolNormalPct: currR.stoolNormalPct,
        bristolCounts: currR.stool.bristolCounts,
        diarrheaCount: currR.stool.diarrheaCount,
        constipationCount: currR.stool.constipationCount,
        topTriggers: currR.topTriggers
      },
      narrative: lines.join("\n")
    });
  } catch (err) {
    console.error("Summary error:", err);
    res.status(500).json({ ok: false, error: "Summary failed" });
  }
});
app.get("/admin", requireAuth, requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get("/terminal", requireAuth, (req, res) => {
  res.type("html").send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>UCell Terminal</title>
  <style>
    html, body { height:100%; margin:0; background:#050607; color:#c8ffd7; font-family: ui-monospace, Menlo, Consolas, monospace; }
    .wrap { min-height:100%; padding:18px; box-sizing:border-box; }
    #timeline { margin-top:14px; opacity:0.55; font-size:12px; line-height:1.5; }
    #input { width:100%; padding:12px; border-radius:10px; border:1px solid rgba(200,255,215,0.18); background:#07090a; color:#c8ffd7; outline:none; font-size:14px; }
    .row { display:flex; gap:10px; align-items:center; margin-top:10px; }
    button { padding:10px 12px; border-radius:10px; border:1px solid rgba(200,255,215,0.22); background:rgba(200,255,215,0.06); color:#c8ffd7; cursor:pointer; }
    a { color:#c8ffd7; }
    #fab {
      position: fixed;
      top: 16px;
      right: 16px;
      width: 44px;
      height: 44px;
      border-radius: 50%;
      border: 1px solid rgba(200,255,215,0.3);
      background: rgba(200,255,215,0.08);
      color: #c8ffd7;
      font-size: 26px;
      line-height: 42px;
      text-align: center;
      cursor: pointer;
      user-select: none;
      z-index: 1000;
    }
    #uploadMenu {
      position: fixed;
      top: 68px;
      right: 16px;
      display: flex;
      flex-direction: column;
      gap: 8px;
      background: #050607;
      border: 1px solid rgba(200,255,215,0.22);
      border-radius: 12px;
      padding: 10px;
      z-index: 1000;
      min-width: 180px;
    }
    #uploadMenu.hidden { display: none; }
  </style>
</head>
<body>
  <div class="wrap">
    <div id="fab">+</div>
    <div id="uploadMenu" class="hidden">
  <button id="uploadStoolPhoto">Upload stool photo</button>
  <button id="uploadMealPhoto">Upload meal photo</button>
  <button id="uploadMedicalRecord">Upload medical record (PDF)</button>
  <button id="uploadFile">Upload file</button>
</div>
    <input id="photoInput" type="file" accept="image/*" capture="environment" style="display:none" />
    <input id="fileInput" type="file" style="display:none" />
    <input id="input" placeholder="Type and press Enter. Prefix with meal:, stool:, symptom:, sleep:, mood:, note:" />
    <div class="row">
      <a href="/admin">Admin</a>
      <form method="POST" action="/logout" style="margin-left:auto;">
        <button type="submit">Logout</button>
      </form>
    </div>
    <div id="timeline"></div>
  </div>
<script>
  const input = document.getElementById("input");
  const timeline = document.getElementById("timeline");
  const fab = document.getElementById("fab");
  const uploadMenu = document.getElementById("uploadMenu");
  const photoInput = document.getElementById("photoInput");
  const fileInput = document.getElementById("fileInput");
  let pendingUploadKind = null;

  fab.addEventListener("click", () => {
    uploadMenu.classList.toggle("hidden");
  });

  document.getElementById("uploadStoolPhoto").addEventListener("click", () => {
    pendingUploadKind = "stool_photo";
    uploadMenu.classList.add("hidden");
    photoInput.value = "";
    photoInput.click();
  });

  document.getElementById("uploadMealPhoto").addEventListener("click", () => {
    pendingUploadKind = "meal_photo";
    uploadMenu.classList.add("hidden");
    photoInput.value = "";
    photoInput.click();
  });

  document.getElementById("uploadFile").addEventListener("click", () => {
    pendingUploadKind = "file";
    uploadMenu.classList.add("hidden");
    fileInput.value = "";
    fileInput.click();
  });
const medRecBtn = document.getElementById("uploadMedicalRecord");
if (medRecBtn) {
  medRecBtn.addEventListener("click", async () => {
    console.log("Medical record button clicked");
    uploadMenu.classList.add("hidden");
    const input = document.createElement("input");
    input.type = "file";
    input.accept = "application/pdf";
    input.style.display = "none";
    document.body.appendChild(input);
    input.addEventListener("change", async () => {
      console.log("File selected:", input.files[0]);
      if (input.files && input.files[0]) {
        const fd = new FormData();
        fd.append("file", input.files[0]);
        console.log("Sending to /process-medical-records");
        try {
          const r = await fetch("/process-medical-records", {
            method: "POST",
            body: fd
          });
          console.log("Response status:", r.status);
          const responseText = await r.text();
          console.log("Response body:", responseText);
          if (!r.ok) {
            alert("Medical record processing failed: " + responseText);
          } else {
            alert("Medical record processed successfully!");
          }
        } catch (err) {
          console.error("Fetch error:", err);
          alert("Network error: " + err.message);
        }
        input.remove();
        await refresh();
      }
    });
    input.click();
  });
} else {
  console.error("uploadMedicalRecord button not found!");
}
  async function handleUpload(file, kind) {
    const fd = new FormData();
    fd.append("file", file);
    fd.append("kind", kind);
    fd.append("text", input.value || "");
    const r = await fetch("/upload", {
      method: "POST",
      body: fd
    });
    if (!r.ok) {
      alert("Upload failed");
      return;
    }
    input.value = "";
    pendingUploadKind = null;
    await refresh();
  }

  photoInput.addEventListener("change", () => {
    if (photoInput.files && photoInput.files[0]) {
      const kind = pendingUploadKind === "stool_photo" ? "stool_photo" : "meal_photo";
      handleUpload(photoInput.files[0], kind);
    }
  });

  fileInput.addEventListener("change", () => {
    if (fileInput.files && fileInput.files[0]) {
      handleUpload(fileInput.files[0], "file");
    }
  });

  function fmtPct(x) {
    return typeof x === "number" ? Math.round(x * 100) + "% confidence" : null;
  }

  async function refresh() {
    const r = await fetch("/logs");
    const j = await r.json();
    if (!j.ok) return;
    const rows = (j.rows || []).slice().reverse();
    timeline.innerHTML = "";
    for (const x of rows) {
      const line = document.createElement("div");
      const ts = new Date(x.ts).toLocaleString();
      const role = x.role;
      let text = x.text || "";
      try {
        const obj = JSON.parse(text);
        if (obj && obj.raw) text = obj.raw;
      } catch (_) {}
      const header = document.createElement("div");
      header.textContent = ts + "  " + role + "  " + text;
      line.appendChild(header);
      if (x.file_name) {
        const mime = String(x.file_type || "").toLowerCase();
        const url = "/uploads/" + encodeURIComponent(x.file_name);
        if (mime.startsWith("image/")) {
          const img = document.createElement("img");
          img.src = url;
          img.alt = x.file_original || "uploaded image";
          img.style.maxWidth = "240px";
          img.style.display = "block";
          img.style.marginTop = "6px";
          img.style.border = "1px solid rgba(200,255,215,0.18)";
          img.style.borderRadius = "10px";
          line.appendChild(img);
          const a = x.ai_analysis || null;
          const box = document.createElement("div");
          box.style.marginTop = "6px";
          box.style.padding = "8px 10px";
          box.style.border = "1px solid rgba(200,255,215,0.14)";
          box.style.borderRadius = "10px";
          box.style.background = "rgba(200,255,215,0.03)";
          box.style.fontSize = "12px";
          box.style.opacity = "0.9";
          if (a && a.kind === "stool_photo_bristol") {
            if (a.status === "ok" && typeof a.bristol === "number") {
              const confText = fmtPct(a.confidence);
              const top = document.createElement("div");
              top.textContent = "Bristol: " + a.bristol + (confText ? " (" + confText + ")" : "");
              box.appendChild(top);
              if (a.rationale) {
                const r2 = document.createElement("div");
                r2.style.marginTop = "4px";
                r2.textContent = "Note: " + a.rationale;
                box.appendChild(r2);
              }
              if (Array.isArray(a.warnings) && a.warnings.length) {
                const w = document.createElement("div");
                w.style.marginTop = "4px";
                w.textContent = "Warnings: " + a.warnings.join("; ");
                box.appendChild(w);
              }
            } else {
              const msg = document.createElement("div");
              msg.textContent = "Bristol: unavailable (" + (a.status || "unknown") + ")";
              box.appendChild(msg);
              if (a.warning) {
                const w = document.createElement("div");
                w.style.marginTop = "4px";
                w.textContent = "Note: " + a.warning;
                box.appendChild(w);
              }
            }
          } else if (a && a.kind === "meal_photo_macros") {
            if (a.status === "ok") {
              const kcal = typeof a.calories === "number" ? Math.round(a.calories) : null;
              const p = typeof a.protein_g === "number" ? Math.round(a.protein_g) : null;
              const c = typeof a.carbs_g === "number" ? Math.round(a.carbs_g) : null;
              const f = typeof a.fat_g === "number" ? Math.round(a.fat_g) : null;
              const confText = fmtPct(a.confidence);
              const top = document.createElement("div");
              const parts = [];
              if (kcal !== null) parts.push(kcal + " kcal");
              if (p !== null) parts.push("P " + p + "g");
              if (c !== null) parts.push("C " + c + "g");
              if (f !== null) parts.push("F " + f + "g");
              top.textContent = "Meal: " + (parts.length ? parts.join(" | ") : "analysis available") + (confText ? " (" + confText + ")" : "");
              box.appendChild(top);
              if (a.summary) {
                const s = document.createElement("div");
                s.style.marginTop = "4px";
                s.textContent = "Note: " + a.summary;
                box.appendChild(s);
              }
            } else {
              const msg = document.createElement("div");
              msg.textContent = "Meal: pending";
              box.appendChild(msg);
            }
          } else {
            const msg = document.createElement("div");
            msg.textContent = "Analysis: pending";
            box.appendChild(msg);
          }
          line.appendChild(box);
        } else {
          const a = document.createElement("a");
          a.href = url;
          a.target = "_blank";
          a.rel = "noopener";
          a.textContent = x.file_original || x.file_name;
          a.style.display = "inline-block";
          a.style.marginTop = "6px";
          line.appendChild(a);
        }
      }
      timeline.appendChild(line);
    }
  }

  input.addEventListener("keydown", async (e) => {
    if (e.key !== "Enter") return;
    const text = input.value.trim();
    if (!text) return;
    input.value = "";
    await fetch("/log", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text })
    });
    await refresh();
  });

  refresh();
</script>
</body>
</html>`);
});

app.get("/logs", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT ts, username, role, text, file_name, file_original, file_type, ai_analysis FROM logs WHERE username = $1 ORDER BY ts DESC LIMIT 200",
      [req.user]
    );
    res.json({ ok: true, rows: result.rows });
  } catch (e) {
    console.error("GET /logs error:", e);
    res.status(500).json({ ok: false, error: "Failed to fetch logs" });
  }
});

app.post("/log", requireAuth, async (req, res) => {
  const rawText = (req.body && typeof req.body.text === "string" ? req.body.text : "") || (req.body && typeof req.body.content === "string" ? req.body.content : "");
  const text = String(rawText).trim();
  if (!text) return res.status(400).json({ ok: false, error: "Empty log" });
  const ts = new Date();
  const m = text.match(/^(meal|beverage|stool|symptom|mood|sleep|note)\s*:\s*(.*)$/i);
  const entryType = m ? m[1].toLowerCase() : "note";
  const entryText = m ? (m[2] || "").trim() : text;
  let bristol = null;
  if (entryType === "stool") {
    const bm = entryText.match(/\b(bristol|bs|type)\s*[:#]?\s*([1-7])\b/i);
    if (bm) bristol = parseInt(bm[2], 10);
  }
  try {
    const payload = { type: entryType, text: entryText, bristol, raw: text };
    await pool.query("INSERT INTO logs (ts, username, role, text) VALUES ($1, $2, $3, $4)", [ts, req.user, "user", JSON.stringify(payload)]);
    await pool.query("INSERT INTO logs (ts, username, role, text) VALUES ($1, $2, $3, $4)", [ts, req.user, "guardian", "Noted. We'll watch for patterns."]);
    res.json({ ok: true });
  } catch (err) {
    console.error("Log entry error:", err);
    res.status(500).json({ error: "Failed to log entry" });
  }
});
app.post("/upload", requireAuth, upload.any(), async (req, res) => {
  const file = (Array.isArray(req.files) && req.files.length > 0) ? req.files[0] : req.file;
  if (!file) {
    return res.status(400).json({ ok: false, error: "no_file_received" });
  }
  const ts = new Date();
  const filePath = path.join(UPLOAD_DIR, file.filename);
  const mime = String(file.mimetype || "").toLowerCase();
  const isImage = mime.startsWith("image/");
  const isHeicLike = mime.includes("heic") || mime.includes("heif") || String(file.originalname || "").toLowerCase().endsWith(".heic");
  let ai_analysis = null;

  function extractOutputText(resp) {
    if (!resp) return "";
    if (typeof resp.output_text === "string" && resp.output_text.trim()) return resp.output_text;
    const out = resp.output;
    if (!Array.isArray(out)) return "";
    const parts = [];
    for (const item of out) {
      const content = item && item.content;
      if (!Array.isArray(content)) continue;
      for (const c of content) {
        if (c && c.type === "output_text" && typeof c.text === "string") {
          parts.push(c.text);
        }
      }
    }
    return parts.join("\n").trim();
  }

  async function callOpenAIJson({ apiKey, model, prompt, dataUrl }) {
    const https = require("https");
    const payload = JSON.stringify({
      model,
      input: [{ role: "user", content: [{ type: "input_text", text: prompt }, { type: "input_image", image_url: dataUrl }] }]
    });
    const responseJson = await new Promise((resolve, reject) => {
      const agent = new https.Agent({ keepAlive: true, minVersion: "TLSv1.2" });
      const req2 = https.request("https://api.openai.com/v1/responses", {
        agent,
        method: "POST",
        headers: {
          Authorization: "Bearer " + apiKey,
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(payload)
        }
      }, (resp) => {
        let data = "";
        resp.on("data", (chunk) => (data += chunk));
        resp.on("end", () => {
          try {
            const parsed = JSON.parse(data);
            if (resp.statusCode < 200 || resp.statusCode >= 300) {
              return reject(new Error(parsed?.error?.message || "OpenAI error"));
            }
            resolve(parsed);
          } catch {
            reject(new Error("Failed to parse OpenAI response"));
          }
        });
      });
      req2.on("error", reject);
      req2.write(payload);
      req2.end();
    });
    const rawText = extractOutputText(responseJson);
    let parsed;
    try {
      parsed = JSON.parse(rawText);
    } catch {
      parsed = null;
    }
    return { parsed, rawText };
  }

  async function detectImageIntent({ apiKey, model, dataUrl }) {
    const prompt = "You are an image intent classifier for a health logging app.\n\nTask:\nClassify the image into exactly ONE of:\n- \"stool\"\n- \"meal\"\n- \"other\"\n\nReturn ONLY valid JSON with this exact schema:\n{\n  \"intent\": \"stool\" | \"meal\" | \"other\",\n  \"confidence\": <number 0-1>,\n  \"rationale\": <short string, <= 12 words>\n}\n\nRules:\n- If you are not confident it is stool or meal, choose \"other\".\n- Do not include extra keys.\n- Do not wrap in markdown.";
    const { parsed } = await callOpenAIJson({ apiKey, model, prompt, dataUrl });
    const intent = typeof parsed?.intent === "string" ? parsed.intent : null;
    const confidence = typeof parsed?.confidence === "number" ? parsed.confidence : null;
    if (!intent || !["stool", "meal", "other"].includes(intent) || confidence === null || confidence < 0 || confidence > 1) {
      return { intent: "other", confidence: 0, rationale: "invalid_router_output" };
    }
    return { intent, confidence, rationale: typeof parsed?.rationale === "string" ? parsed.rationale : "" };
  }

  async function analyzeMealMacros({ apiKey, model, dataUrl }) {
    const prompt = `You are a meal photo analyzer for a digestive health tracking app.

Task:
From a single meal photo, estimate:
1. Macros: calories, protein grams, carbs grams, fat grams
2. Trigger detection: Identify potential digestive triggers present in the meal

Return ONLY valid JSON with this exact schema:
{
  "calories": <number>,
  "protein_g": <number>,
  "carbs_g": <number>,
  "fat_g": <number>,
  "confidence": <number 0-1>,
  "meal_description": <brief description of the meal, 10-20 words>,
  "detected_triggers": [<array of strings from this list: "high_fat", "dairy", "spicy", "alcohol", "caffeine", "high_fiber", "gluten", "sugar", "fried">],
  "trigger_details": <string explaining which specific foods contain which triggers, 20-40 words>,
  "warnings": <array of short strings>
}

Trigger detection rules:
- "high_fat": fried foods, cream sauces, cheese-heavy dishes, fatty meats, butter-heavy items
- "dairy": milk, cheese, cream, yogurt, ice cream, whey
- "spicy": hot peppers, hot sauce, spicy seasonings, curry
- "alcohol": beer, wine, cocktails, spirits
- "caffeine": coffee, tea, energy drinks, chocolate
- "high_fiber": beans, lentils, bran, raw vegetables, whole grains
- "gluten": bread, pasta, wheat products, flour-based items
- "sugar": desserts, candy, sweetened drinks, pastries
- "fried": deep-fried or pan-fried items

Rules:
- Provide best-effort estimates even if uncertain
- Only include triggers you can actually SEE in the photo
- Be specific in trigger_details (e.g. "cheese sauce likely high-fat and dairy")
- If not a meal photo, set all numbers to 0, confidence to 0, detected_triggers to [], and add a warning
- Do not include extra keys
- Do not wrap in markdown`;

    const { parsed, rawText } = await callOpenAIJson({ apiKey, model, prompt, dataUrl });
    const calories = typeof parsed?.calories === "number" ? parsed.calories : null;
    const protein_g = typeof parsed?.protein_g === "number" ? parsed.protein_g : null;
    const carbs_g = typeof parsed?.carbs_g === "number" ? parsed.carbs_g : null;
    const fat_g = typeof parsed?.fat_g === "number" ? parsed.fat_g : null;
    const confidence = typeof parsed?.confidence === "number" ? parsed.confidence : null;
    const validNums = calories !== null && calories >= 0 && protein_g !== null && protein_g >= 0 && carbs_g !== null && carbs_g >= 0 && fat_g !== null && fat_g >= 0 && confidence !== null && confidence >= 0 && confidence <= 1;
    if (!validNums) {
      return { status: "failed_validation", raw_output_text: rawText || null };
    }
    return {
      status: "ok",
      calories,
      protein_g,
      carbs_g,
      fat_g,
      confidence,
      meal_description: typeof parsed?.meal_description === "string" ? parsed.meal_description : "",
      detected_triggers: Array.isArray(parsed?.detected_triggers) ? parsed.detected_triggers : [],
      trigger_details: typeof parsed?.trigger_details === "string" ? parsed.trigger_details : "",
      warnings: Array.isArray(parsed?.warnings) ? parsed.warnings : []
    };
  }
  

  try {
    const apiKey = process.env.OPENAI_API_KEY;
    const visionModel = process.env.UCELL_VISION_MODEL || "gpt-4o";
    let image_intent = "other";
    let image_intent_confidence = 0;
    if (isImage && apiKey && !isHeicLike) {
      const b64 = fs.readFileSync(filePath).toString("base64");
      const dataUrl = "data:" + mime + ";base64," + b64;
      const routed = await detectImageIntent({ apiKey, model: visionModel, dataUrl });
      image_intent = routed.intent || "other";
      image_intent_confidence = typeof routed.confidence === "number" ? routed.confidence : 0;
    }
    const INTENT_THRESHOLD = 0.70;
    const isStoolIntent = isImage && image_intent === "stool" && image_intent_confidence >= INTENT_THRESHOLD;
    const isMealIntent = isImage && image_intent === "meal" && image_intent_confidence >= INTENT_THRESHOLD;
    console.log("[UPLOAD ROUTER]", "name:", file.originalname, "mime:", mime, "intent:", image_intent, "confidence:", image_intent_confidence, "isMeal:", isMealIntent, "isStool:", isStoolIntent, "heicLike:", isHeicLike);
    if (isImage && isHeicLike) {
      ai_analysis = { kind: "image", status: "skipped_unsupported_format", model: visionModel, created_at: ts.toISOString(), warning: "HEIC/HEIF not supported for analysis. Use JPG or PNG." };
    } else if (isMealIntent) {
        console.log("[MEAL ANALYSIS] Starting...");
      if (!apiKey) {
        ai_analysis = { kind: "meal_photo_macros", status: "skipped_missing_api_key", model: visionModel, created_at: ts.toISOString(), warning: "OPENAI_API_KEY missing" };
      } else {
        const b64 = fs.readFileSync(filePath).toString("base64");
        const dataUrl = "data:" + mime + ";base64," + b64;
        const meal = await analyzeMealMacros({ apiKey, model: visionModel, dataUrl });
        console.log("[MEAL ANALYSIS] Result:", meal);
        if (!meal || meal.status !== "ok") {
          ai_analysis = { kind: "meal_photo_macros", status: meal?.status || "meal_analyzer_no_result", model: visionModel, created_at: ts.toISOString(), raw_output_text: meal?.raw_output_text || null };
        } else {
          ai_analysis = { kind: "meal_photo_macros", status: "ok", model: visionModel, created_at: ts.toISOString(), intent: image_intent, intent_confidence: image_intent_confidence, calories: meal.calories, protein_g: meal.protein_g, carbs_g: meal.carbs_g, fat_g: meal.fat_g, confidence: meal.confidence, notes: meal.notes, warnings: meal.warnings };
        }
      }
    } else if (isStoolIntent) {
      if (!apiKey) {
        ai_analysis = { kind: "stool_photo_bristol", status: "skipped_missing_api_key", model: visionModel, created_at: ts.toISOString(), warning: "OPENAI_API_KEY missing" };
      } else {
        const b64 = fs.readFileSync(filePath).toString("base64");
        const dataUrl = "data:" + mime + ";base64," + b64;
        const prompt = "You are a clinically cautious stool-form classifier.\nGiven a single stool photo, estimate the Bristol Stool Scale class (1-7).\n\nReturn ONLY valid JSON with this exact schema:\n{\n  \"bristol\": <integer 1-7>,\n  \"confidence\": <number 0-1>,\n  \"rationale\": <short string, <= 20 words>,\n  \"warnings\": <array of short strings>\n}\n\nRules:\n- If the photo is not clearly a stool photo, set bristol = 0 and confidence = 0 and add a warning.\n- If visibility is poor, lower confidence and add a warning.\n- Do not include extra keys. Do not wrap in markdown.";
        const { parsed, rawText } = await callOpenAIJson({ apiKey, model: visionModel, prompt, dataUrl });
        const bristol = Number.isInteger(parsed?.bristol) ? parsed.bristol : null;
        const confidence = typeof parsed?.confidence === "number" ? parsed.confidence : null;
        if (bristol === null || confidence === null || bristol < 0 || bristol > 7 || confidence < 0 || confidence > 1) {
          ai_analysis = { kind: "stool_photo_bristol", status: "failed_validation", model: visionModel, created_at: ts.toISOString(), raw_output_text: rawText || null };
        } else {
          ai_analysis = { kind: "stool_photo_bristol", status: "ok", model: visionModel, created_at: ts.toISOString(), bristol, confidence, rationale: parsed?.rationale || "", warnings: Array.isArray(parsed?.warnings) ? parsed.warnings : [] };
        }
      }
    }
// Build proper text entry for meal photos
let logText = req.body?.text || "";
if (!logText && ai_analysis && ai_analysis.kind === "meal_photo_macros" && ai_analysis.status === "ok") {
  const desc = ai_analysis.meal_description || "Meal photo";
  const triggers = ai_analysis.detected_triggers || [];
  const triggerText = triggers.length ? " (triggers: " + triggers.join(", ") + ")" : "";
  logText = JSON.stringify({ 
    type: "meal", 
    text: desc + triggerText,
    raw: desc
  });
} else if (!logText && ai_analysis && ai_analysis.kind === "stool_photo_bristol") {
  logText = JSON.stringify({
    type: "stool",
    text: "Stool photo",
    bristol: ai_analysis.bristol || null,
    raw: "Stool photo"
  });
} else if (!logText) {
  logText = isImage ? "Photo uploaded" : "File uploaded";
}

await pool.query("INSERT INTO logs (ts, username, role, text, file_name, file_original, file_type, ai_analysis) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)", [ts, req.user, "user", logText, file.filename, file.originalname, file.mimetype, ai_analysis]);
    return res.json({ ok: true });
  } catch (e) {
    console.error("Upload analysis error:", e?.message || e);
    try {
      await pool.query("INSERT INTO logs (ts, username, role, text) VALUES ($1, $2, $3, $4)", [new Date(), req.user, "system", "Image analysis unavailable. Photo saved successfully."]);
    } catch (logErr) {
      console.error("Failed to log analysis failure:", logErr);
    }
    return res.json({ ok: true, analysis: "skipped" });
  }
});
app.post("/process-medical-records", requireAuth, upload.any(), async (req, res) => {
  const file = (Array.isArray(req.files) && req.files.length > 0) ? req.files[0] : req.file;
  if (!file) {
    return res.status(400).json({ error: "No file uploaded" });
  }

  const filePath = path.join(UPLOAD_DIR, file.filename);
  const isPDF = String(file.mimetype || "").toLowerCase().includes("pdf");

  if (!isPDF) {
    return res.status(400).json({ error: "Only PDF files supported for medical record processing" });
  }

  try {
    const pdfParse = require("pdf-parse");
    const dataBuffer = fs.readFileSync(filePath);
    const pdfData = await pdfParse(dataBuffer);
    const extractedText = pdfData.text || "";

    if (!extractedText.trim()) {
      return res.status(400).json({ error: "Could not extract text from PDF" });
    }

    const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
    if (!ANTHROPIC_API_KEY) {
      await pool.query(
        "INSERT INTO logs (ts, username, role, text, file_name, file_original, file_type) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        [new Date(), req.user, "system", "Medical record uploaded but ANTHROPIC_API_KEY not configured. Text extracted but not analyzed.", file.filename, file.originalname, file.mimetype]
      );
      return res.json({ ok: true, status: "extracted_text_only", warning: "ANTHROPIC_API_KEY missing" });
    }

    const https = require("https");
    const payload = JSON.stringify({
      model: "claude-sonnet-4-20250514",
      max_tokens: 2000,
      messages: [
        {
          role: "user",
          content: `You are a medical record analyzer for a health tracking app called UCell Guardian.

The user (${req.user}) has uploaded a medical record. Extract the following structured data in JSON format:

{
  "document_type": "lab_results" | "clinical_notes" | "procedure_report" | "other",
  "date": "YYYY-MM-DD or null",
  "provider": "string or null",
  "key_findings": ["finding1", "finding2"],
  "medications": ["med1", "med2"],
  "diagnoses": ["diagnosis1", "diagnosis2"],
  "lab_values": [{"test": "test_name", "value": "value", "unit": "unit", "flag": "normal|high|low"}],
  "summary": "2-3 sentence clinical summary in a warm, Guardian-like tone"
}

Medical record text:
${extractedText.substring(0, 15000)}

Return ONLY valid JSON. No markdown. No extra text.`
        }
      ]
    });

    const anthropicResponse = await new Promise((resolve, reject) => {
      const req2 = https.request("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: {
          "x-api-key": ANTHROPIC_API_KEY,
          "anthropic-version": "2023-06-01",
          "content-type": "application/json"
        }
      }, (resp) => {
        let data = "";
        resp.on("data", (chunk) => (data += chunk));
        resp.on("end", () => {
          if (resp.statusCode < 200 || resp.statusCode >= 300) {
            return reject(new Error("Anthropic API error: " + data));
          }
          try {
            resolve(JSON.parse(data));
          } catch {
            reject(new Error("Failed to parse Anthropic response"));
          }
        });
      });
      req2.on("error", reject);
      req2.write(payload);
      req2.end();
    });

    const assistantText = anthropicResponse?.content?.find(c => c.type === "text")?.text || "";
    let parsedData;
    try {
      parsedData = JSON.parse(assistantText);
    } catch {
      parsedData = { summary: "Medical record processed but structured extraction failed.", raw_text: assistantText };
    }

    const medicalData = {
      kind: "medical_record_analysis",
      status: "ok",
      document_type: parsedData.document_type || "other",
      date: parsedData.date || null,
      provider: parsedData.provider || null,
      key_findings: parsedData.key_findings || [],
      medications: parsedData.medications || [],
      diagnoses: parsedData.diagnoses || [],
      lab_values: parsedData.lab_values || [],
      summary: parsedData.summary || "",
      extracted_at: new Date().toISOString()
    };

    await pool.query(
      "INSERT INTO logs (ts, username, role, text, file_name, file_original, file_type, ai_analysis) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
      [new Date(), req.user, "user", "Medical record uploaded", file.filename, file.originalname, file.mimetype, medicalData]
    );

    const guardianMessage = parsedData.summary || "I've reviewed your medical record. I'll keep this in context as we track your health patterns.";
    
    await pool.query(
      "INSERT INTO logs (ts, username, role, text) VALUES ($1, $2, $3, $4)",
      [new Date(), req.user, "guardian", guardianMessage]
    );

    res.json({ ok: true, status: "analyzed", summary: guardianMessage, data: medicalData });

  } catch (err) {
    console.error("Medical record processing error:", err);
    console.error("Error stack:", err.stack);
    console.error("File received:", file);
    await pool.query(
      "INSERT INTO logs (ts, username, role, text) VALUES ($1, $2, $3, $4)",
      [new Date(), req.user, "system", "Medical record processing failed: " + (err.message || "unknown error")]
    );
    res.status(500).json({ error: "Processing failed", details: err.message });
  }
});
app.get("/health", (req, res) => {
  res.json({ ok: true, status: "up" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("UCell server running on http://localhost:" + PORT);
});
