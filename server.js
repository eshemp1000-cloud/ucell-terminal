const express = require("express");
const fs = require("fs");
const path = require("path");
const multer = require("multer");
const crypto = require("crypto");
const { Pool } = require('pg');

const app = express();
app.use(express.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

const UPLOAD_DIR = path.join(__dirname, "uploads");
const VISION_API_KEY = "AIzaSyAlU7VoOIFnQ9CNQvIY3fgrAsRK_JJ4xeI";

// PostgreSQL connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR);
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + "-" + file.originalname;
    cb(null, uniqueName);
  }
});

const upload = multer({ storage });

// Initialize database
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
      
      CREATE TABLE IF NOT EXISTS sessions (
        token VARCHAR(255) PRIMARY KEY,
        username VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_logs_username ON logs(username);
      CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts DESC);
    `);
    console.log('✅ Database tables initialized');
  } catch (err) {
    console.error('❌ Database initialization error:', err);
  }
}

initDatabase();

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

async function initializeUsers() {
  try {
    const result = await pool.query('SELECT COUNT(*) FROM users');
    if (parseInt(result.rows[0].count) === 0) {
      await pool.query(
        'INSERT INTO users (username, password, is_admin) VALUES ($1, $2, $3)',
        ['james', hashPassword('ucell2024'), true]
      );
      console.log('✅ Created default admin user: james / ucell2024');
    }
  } catch (err) {
    console.error('User initialization error:', err);
  }
}

initializeUsers();

function requireAuth(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  pool.query('SELECT username FROM sessions WHERE token = $1', [token])
    .then(result => {
      if (result.rows.length === 0) {
        return res.status(401).json({ error: 'Not authenticated' });
      }
      req.user = result.rows[0].username;
      next();
    })
    .catch(err => {
      console.error('Auth error:', err);
      res.status(500).json({ error: 'Auth failed' });
    });
}

function requireAdmin(req, res, next) {
  pool.query('SELECT is_admin FROM users WHERE username = $1', [req.user])
    .then(result => {
      if (result.rows.length === 0 || !result.rows[0].is_admin) {
        return res.status(403).json({ error: 'Admin access required' });
      }
      next();
    })
    .catch(err => {
      console.error('Admin check error:', err);
      res.status(500).json({ error: 'Auth check failed' });
    });
}

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    
    if (result.rows.length === 0 || result.rows[0].password !== hashPassword(password)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = generateSessionToken();
    await pool.query('INSERT INTO sessions (token, username) VALUES ($1, $2)', [token, username]);
    
    res.json({
      token,
      username,
      isAdmin: result.rows[0].is_admin || false
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post("/api/logout", requireAuth, async (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  try {
    await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
    res.json({ ok: true });
  } catch (err) {
    console.error('Logout error:', err);
    res.status(500).json({ error: 'Logout failed' });
  }
});

app.get("/api/me", requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT is_admin FROM users WHERE username = $1', [req.user]);
    res.json({
      username: req.user,
      isAdmin: result.rows[0]?.is_admin || false
    });
  } catch (err) {
    console.error('Me error:', err);
    res.status(500).json({ error: 'Failed to get user info' });
  }
});

app.get("/api/admin/users", requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT username, is_admin, created_at FROM users ORDER BY created_at DESC');
    const users = result.rows.map(row => ({
      username: row.username,
      isAdmin: row.is_admin,
      createdAt: row.created_at.toISOString()
    }));
    res.json(users);
  } catch (err) {
    console.error('Get users error:', err);
    res.status(500).json({ error: 'Failed to get users' });
  }
});

app.post("/api/admin/users", requireAuth, requireAdmin, async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  
  try {
    await pool.query(
      'INSERT INTO users (username, password, is_admin) VALUES ($1, $2, $3)',
      [username, hashPassword(password), false]
    );
    res.json({ ok: true, username });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(400).json({ error: 'Username already exists' });
    }
    console.error('Create user error:', err);
    res.status(500).json({ error: 'Failed to create user' });
  }
});

app.delete("/api/admin/users/:username", requireAuth, requireAdmin, async (req, res) => {
  const { username } = req.params;
  
  if (username === req.user) {
    return res.status(400).json({ error: 'Cannot delete your own account' });
  }
  
  try {
    await pool.query('DELETE FROM users WHERE username = $1', [username]);
    res.json({ ok: true });
  } catch (err) {
    console.error('Delete user error:', err);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

async function analyzeImage(imagePath) {
  try {
    const imageBuffer = fs.readFileSync(imagePath);
    const base64Image = imageBuffer.toString('base64');

    const response = await fetch(
      `https://vision.googleapis.com/v1/images:annotate?key=${VISION_API_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          requests: [{
            image: { content: base64Image },
            features: [
              { type: 'LABEL_DETECTION', maxResults: 10 },
              { type: 'OBJECT_LOCALIZATION', maxResults: 10 },
              { type: 'IMAGE_PROPERTIES' }
            ]
          }]
        })
      }
    );

    const data = await response.json();
    
    if (!data.responses || !data.responses[0]) {
      return { type: 'unknown', analysis: 'Could not analyze image' };
    }

    const labels = data.responses[0].labelAnnotations || [];
    const objects = data.responses[0].localizedObjectAnnotations || [];
    const colors = data.responses[0].imagePropertiesAnnotation?.dominantColors?.colors || [];
    
    const detectedLabels = labels.map(l => l.description.toLowerCase());
    const detectedObjects = objects.map(o => o.name.toLowerCase());
    const allDetected = [...detectedLabels, ...detectedObjects];

    const hasBrownColor = colors.some(color => {
      const r = color.color.red || 0;
      const g = color.color.green || 0;
      const b = color.color.blue || 0;
      return (r > 100 && r < 200 && g > 70 && g < 150 && b > 30 && b < 100);
    });

    const hasToiletIndicator = allDetected.some(item => 
      item.includes('toilet') || item.includes('bathroom') || 
      item.includes('porcelain') || item.includes('ceramic') || item.includes('bowl')
    );

    if (hasToiletIndicator || hasBrownColor) {
      return analyzeStoolImage(allDetected, colors);
    }

    const foodKeywords = [
      'food', 'dish', 'meal', 'cuisine', 'salad', 'sandwich', 'burger', 
      'pizza', 'pasta', 'rice', 'vegetable', 'fruit', 'meat', 'plate',
      'sushi', 'burrito', 'soup', 'breakfast', 'lunch', 'dinner', 'snack',
      'dessert', 'bread', 'cheese', 'chicken', 'beef', 'pork', 'fish'
    ];

    const isFood = allDetected.some(item => 
      foodKeywords.some(kw => item.includes(kw))
    );

    if (isFood) {
      return analyzeFoodImage(allDetected, labels);
    } else {
      return {
        type: 'photo',
        analysis: `Detected: ${allDetected.slice(0, 5).join(', ')}`
      };
    }

  } catch (error) {
    console.error('Vision API error:', error);
    return { type: 'unknown', analysis: 'Analysis failed' };
  }
}

function analyzeFoodImage(detected, labels) {
  const foodTypes = {
    'salad': ['salad', 'lettuce', 'vegetable', 'greens'],
    'burrito': ['burrito', 'wrap', 'tortilla', 'mexican'],
    'sushi': ['sushi', 'japanese', 'rice', 'fish', 'seafood'],
    'soup': ['soup', 'broth', 'stew'],
    'sandwich': ['sandwich', 'bread', 'burger'],
    'pasta': ['pasta', 'noodle', 'spaghetti'],
    'pizza': ['pizza'],
    'rice bowl': ['rice', 'bowl', 'grain'],
    'breakfast': ['breakfast', 'eggs', 'bacon', 'pancake'],
  };

  let identifiedType = 'meal';
  for (const [type, keywords] of Object.entries(foodTypes)) {
    if (detected.some(item => keywords.some(kw => item.includes(kw)))) {
      identifiedType = type;
      break;
    }
  }

  const nutritionEstimates = {
    'salad': { calories: 250, protein: 8, fat: 12, fiber: 6 },
    'burrito': { calories: 650, protein: 25, fat: 28, fiber: 10 },
    'sushi': { calories: 400, protein: 20, fat: 8, fiber: 3 },
    'soup': { calories: 200, protein: 10, fat: 6, fiber: 4 },
    'sandwich': { calories: 450, protein: 18, fat: 16, fiber: 5 },
    'pasta': { calories: 550, protein: 15, fat: 12, fiber: 4 },
    'pizza': { calories: 700, protein: 25, fat: 30, fiber: 3 },
    'rice bowl': { calories: 500, protein: 20, fat: 15, fiber: 5 },
    'breakfast': { calories: 500, protein: 20, fat: 22, fiber: 3 },
    'meal': { calories: 450, protein: 18, fat: 15, fiber: 5 }
  };

  const nutrition = nutritionEstimates[identifiedType] || nutritionEstimates['meal'];

  return {
    type: 'food',
    foodType: identifiedType,
    nutrition: nutrition,
    analysis: `${identifiedType.charAt(0).toUpperCase() + identifiedType.slice(1)} - Est: ${nutrition.calories}cal, ${nutrition.protein}g protein, ${nutrition.fat}g fat, ${nutrition.fiber}g fiber`
  };
}

async function analyzeStoolImage(detected, colors) {
  let bristolType = null;
  let bristolDescription = '';
  
  if (colors && colors.length > 0) {
    const dominantColor = colors[0].color;
    const r = dominantColor.red || 0;
    const g = dominantColor.green || 0;
    const b = dominantColor.blue || 0;
    
    const brightness = (r + g + b) / 3;
    const yellowness = (r + g) / 2 - b;
    
    // Type 7: Very light, yellowish, watery
    if (brightness > 180 && yellowness > 40) {
      bristolType = 7;
      bristolDescription = 'Type 7: Entirely liquid (severe diarrhea)';
    }
    // Type 6: Light brown, mushy
    else if (brightness > 150 && yellowness > 20) {
      bristolType = 6;
      bristolDescription = 'Type 6: Mushy with ragged edges (diarrhea)';
    }
    // Type 5: Medium-light brown, soft blobs
    else if (brightness > 120 && r > g && g > b) {
      bristolType = 5;
      bristolDescription = 'Type 5: Soft blobs with clear edges (mild diarrhea)';
    }
    // Type 3-4: Medium brown (normal range)
    else if (brightness > 80 && brightness < 130 && r > g && g > b) {
      if (g - b > 30) {
        bristolType = 4;
        bristolDescription = 'Type 4: Smooth and soft (ideal/normal)';
      } else {
        bristolType = 3;
        bristolDescription = 'Type 3: Sausage-shaped with cracks (normal)';
      }
    }
    // Type 2: Dark brown, lumpy
    else if (brightness < 80 && r > 100) {
      bristolType = 2;
      bristolDescription = 'Type 2: Lumpy and sausage-like (mild constipation)';
    }
    // Type 1: Very dark, hard
    else if (brightness < 60) {
      bristolType = 1;
      bristolDescription = 'Type 1: Separate hard lumps (severe constipation)';
    }
    else {
      bristolType = 4;
      bristolDescription = 'Type 4: Smooth and soft (normal/default)';
    }
  } else {
    bristolType = 4;
    bristolDescription = 'Type 4: Smooth and soft (normal/default)';
  }

  return {
    type: 'stool',
    bristolScale: {
      type: bristolType,
      description: bristolDescription
    },
    detectedLabels: detected.slice(0, 5),
    analysis: `Stool logged - ${bristolDescription}`
  };
}

app.get("/", (req, res) => {
  res.send(`
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>UCell Terminal</title>
  <style>
    :root {
      --bg: #0b0f14;
      --fg: #e9eef7;
      --muted: rgba(233, 238, 247, 0.35);
      --hairline: rgba(233, 238, 247, 0.08);
    }
    * { box-sizing: border-box; }
    html, body {
      margin: 0;
      padding: 0;
      background: var(--bg);
      color: var(--fg);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }
    body { min-height: 100vh; padding: 12px; }
    #login-screen {
      max-width: 400px;
      margin: 100px auto;
      padding: 20px;
    }
    #login-screen h1 {
      font-size: 24px;
      margin-bottom: 20px;
      letter-spacing: 0.2em;
    }
    #login-screen input {
      width: 100%;
      padding: 12px;
      margin-bottom: 12px;
      background: transparent;
      border: 1px solid var(--hairline);
      color: var(--fg);
      font-family: inherit;
      font-size: 16px;
    }
    #login-screen button {
      width: 100%;
      padding: 12px;
      background: transparent;
      border: 1px solid var(--hairline);
      color: var(--fg);
      font-family: inherit;
      font-size: 16px;
      cursor: pointer;
      -webkit-tap-highlight-color: transparent;
    }
    #login-screen button:active {
      background: rgba(233, 238, 247, 0.05);
    }
    .error {
      color: #ff6b6b;
      font-size: 14px;
      margin-top: 10px;
    }
    #app { display: none; }
    #input-container {
      position: sticky;
      top: 8px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    #input {
      flex: 1;
      height: 44px;
      padding: 10px 12px;
      font-size: 18px;
      background: transparent;
      color: var(--fg);
      border: none;
      border-bottom: 1px solid var(--hairline);
      outline: none;
      caret-color: var(--fg);
      animation: pulse-caret 2s ease-in-out infinite;
    }
    @keyframes pulse-caret {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.4; }
    }
    #add-btn {
      width: 32px;
      height: 32px;
      background: transparent;
      border: 1px solid var(--hairline);
      border-radius: 50%;
      color: var(--muted);
      font-size: 20px;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }
    #add-btn:active {
      background: rgba(233, 238, 247, 0.05);
    }
    #upload-menu {
      position: fixed;
      bottom: 60px;
      right: 12px;
      background: #1a1f28;
      border: 1px solid var(--hairline);
      border-radius: 8px;
      padding: 8px;
      display: none;
      flex-direction: column;
      gap: 4px;
      z-index: 1000;
    }
    #upload-menu.active { display: flex; }
    .upload-option {
      padding: 12px 16px;
      background: transparent;
      border: none;
      color: var(--fg);
      font-family: inherit;
      font-size: 14px;
      text-align: left;
      cursor: pointer;
      border-radius: 4px;
    }
    .upload-option:active {
      background: rgba(233, 238, 247, 0.08);
    }
    #timeline {
      margin-top: 16px;
      font-size: 13px;
      line-height: 18px;
      color: var(--muted);
    }
    .entry {
      padding: 6px 0;
      border-top: 1px solid rgba(233,238,247,0.05);
      white-space: pre-wrap;
    }
    .entry img {
      max-width: 200px;
      margin-top: 8px;
      border-radius: 4px;
      border: 1px solid var(--hairline);
    }
    .entry a {
      color: var(--muted);
      text-decoration: underline;
    }
    .analyzing {
      color: rgba(233, 238, 247, 0.5);
      font-style: italic;
    }
    #brand {
      position: fixed;
      left: 12px;
      bottom: 10px;
      font-size: 12px;
      letter-spacing: 0.28em;
      color: var(--muted);
      cursor: pointer;
      user-select: none;
    }
    .hidden { display: none; }
    #admin-panel { padding: 20px; }
    #admin-panel h2 {
      font-size: 20px;
      margin-bottom: 20px;
    }
    .user-list { margin-bottom: 30px; }
    .user-item {
      padding: 12px;
      border: 1px solid var(--hairline);
      margin-bottom: 8px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .delete-btn {
      padding: 6px 12px;
      background: transparent;
      border: 1px solid #ff6b6b;
      color: #ff6b6b;
      cursor: pointer;
      font-size: 12px;
    }
    .add-user-form input {
      width: 100%;
      padding: 12px;
      margin-bottom: 12px;
      background: transparent;
      border: 1px solid var(--hairline);
      color: var(--fg);
      font-family: inherit;
    }
    .add-user-form button {
      padding: 12px 24px;
      background: transparent;
      border: 1px solid var(--hairline);
      color: var(--fg);
      cursor: pointer;
    }
  </style>
</head>
<body>
  <div id="login-screen">
    <h1>UCell</h1>
    <input type="text" id="login-username" placeholder="Username" autocomplete="username">
    <input type="password" id="login-password" placeholder="Password" autocomplete="current-password">
    <button id="login-btn" type="button">Login</button>
    <div id="login-error" class="error"></div>
  </div>
  <div id="app">
    <div id="input-container">
      <input id="input" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" placeholder="type and press enter" />
      <button id="add-btn">+</button>
    </div>
    <div id="upload-menu">
      <button class="upload-option" id="photo-btn">📷 Photo</button>
      <button class="upload-option" id="file-btn">📄 File</button>
    </div>
    <input type="file" id="photo-input" accept="image/*" class="hidden">
    <input type="file" id="file-input" accept=".pdf,.doc,.docx,.txt" class="hidden">
    <div id="timeline"></div>
    <div id="brand" style="font-size: 18px; padding: 15px; cursor: pointer;">UCell</div>
  </div>
  <script>
    let authToken = localStorage.getItem('ucell_token');
    let isAdmin = false;
    const loginScreen = document.getElementById('login-screen');
    const app = document.getElementById('app');
    const loginBtn = document.getElementById('login-btn');
    const loginError = document.getElementById('login-error');
    const input = document.getElementById('input');
    const timeline = document.getElementById('timeline');
    const brand = document.getElementById('brand');
    const addBtn = document.getElementById('add-btn');
    const uploadMenu = document.getElementById('upload-menu');
    const photoBtn = document.getElementById('photo-btn');
    const fileBtn = document.getElementById('file-btn');
    const photoInput = document.getElementById('photo-input');
    const fileInput = document.getElementById('file-input');

    async function checkAuth() {
      if (!authToken) return false;
      try {
        const res = await fetch('/api/me', {
          headers: { 'Authorization': 'Bearer ' + authToken }
        });
        if (res.ok) {
          const data = await res.json();
          isAdmin = data.isAdmin;
          return true;
        }
      } catch (err) {
        console.error('Auth check failed:', err);
      }
      authToken = null;
      localStorage.removeItem('ucell_token');
      return false;
    }

    async function login() {
      const username = document.getElementById('login-username').value;
      const password = document.getElementById('login-password').value;
      loginError.textContent = '';
      try {
        const res = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
        if (res.ok) {
          const data = await res.json();
          authToken = data.token;
          isAdmin = data.isAdmin;
          localStorage.setItem('ucell_token', authToken);
          showApp();
        } else {
          loginError.textContent = 'Invalid username or password';
        }
      } catch (err) {
        console.error('Login error:', err);
        loginError.textContent = 'Login failed - check connection';
      }
    }

    function showApp() {
      loginScreen.style.display = 'none';
      app.style.display = 'block';
      input.focus();
      loadHistory();
    }

    loginBtn.addEventListener('click', function(e) {
      e.preventDefault();
      login();
    });
    
    loginBtn.addEventListener('touchend', function(e) {
      e.preventDefault();
      login();
    });
    
    document.getElementById('login-password').addEventListener('keydown', function(e) {
      if (e.key === 'Enter') {
        e.preventDefault();
        login();
      }
    });

    function renderEntry(entry) {
      const div = document.createElement("div");
      div.className = "entry";
      let html = entry.text || "";
      if (entry.file) {
        if (entry.file.type === "image") {
          html += '<br><img src="/uploads/' + entry.file.name + '" alt="uploaded image">';
        } else {
          html += '<br><a href="/uploads/' + entry.file.name + '" target="_blank">📎 ' + entry.file.original + '</a>';
        }
      }
      div.innerHTML = html;
      return div;
    }

    async function loadHistory() {
      try {
        const res = await fetch("/logs", {
          headers: { 'Authorization': 'Bearer ' + authToken }
        });
        const logs = await res.json();
        if (!Array.isArray(logs)) return;
        timeline.innerHTML = "";
        const reversed = logs.slice().reverse();
        for (const entry of reversed) {
          if (entry && entry.role === "user") {
            timeline.appendChild(renderEntry(entry));
          } else if (entry && entry.role === "guardian") {
            const div = document.createElement("div");
            div.className = "entry";
            div.textContent = entry.text;
            timeline.appendChild(div);
          }
        }
      } catch (err) {
        console.error('Load history failed:', err);
      }
    }

    addBtn.addEventListener("click", function() {
      uploadMenu.classList.toggle("active");
    });

    document.addEventListener("click", function(e) {
      if (!addBtn.contains(e.target) && !uploadMenu.contains(e.target)) {
        uploadMenu.classList.remove("active");
      }
    });

    photoBtn.addEventListener("click", function() {
      photoInput.click();
      uploadMenu.classList.remove("active");
    });

    photoInput.addEventListener("change", async function(e) {
      const file = e.target.files[0];
      if (!file) return;
      const analyzingDiv = document.createElement("div");
      analyzingDiv.className = "entry analyzing";
      analyzingDiv.textContent = "📷 Analyzing photo...";
      timeline.insertBefore(analyzingDiv, timeline.firstChild);
      const formData = new FormData();
      formData.append("file", file);
      try {
        const res = await fetch("/upload", {
          method: "POST",
          headers: { 'Authorization': 'Bearer ' + authToken },
          body: formData
        });
        if (res.ok) {
          loadHistory();
        }
      } catch (err) {
        analyzingDiv.textContent = "Upload failed";
      }
      photoInput.value = "";
    });

    fileBtn.addEventListener("click", function() {
      fileInput.click();
      uploadMenu.classList.remove("active");
    });

    fileInput.addEventListener("change", async function(e) {
      const file = e.target.files[0];
      if (!file) return;
      const formData = new FormData();
      formData.append("file", file);
      formData.append("text", "File uploaded: " + file.name);
      try {
        const res = await fetch("/upload", {
          method: "POST",
          headers: { 'Authorization': 'Bearer ' + authToken },
          body: formData
        });
        if (res.ok) {
          loadHistory();
        }
      } catch (err) {
        console.error("Upload failed:", err);
      }
      fileInput.value = "";
    });

    let tapCount = 0;
    let tapTimer = null;
    brand.addEventListener("click", function() {
      tapCount++;
      if (tapCount === 1) {
        tapTimer = setTimeout(function() { tapCount = 0; }, 1000);
      }
      if (tapCount === 3) {
        clearTimeout(tapTimer);
        tapCount = 0;
        openDashboard();
      }
    });

    async function openDashboard() {
      if (isAdmin) {
        showAdminPanel();
      } else {
        showUserDashboard();
      }
    }

    async function showUserDashboard() {
      const res = await fetch("/logs", {
        headers: { 'Authorization': 'Bearer ' + authToken }
      });
      const logs = await res.json();
      const userLogs = logs.filter(function(e) { return e.role === "user"; });
      const days = new Set(userLogs.map(function(e) { return e.ts.split("T")[0]; })).size;
      document.body.innerHTML = '<div style="padding: 20px; text-align: center;"><div style="font-size: 48px; margin-bottom: 20px; color: var(--fg);">' + userLogs.length + '</div><div style="font-size: 14px; color: var(--muted); margin-bottom: 10px;">entries logged</div><div style="font-size: 14px; color: var(--muted); margin-bottom: 40px;">active for ' + days + ' days</div><button id="back" style="padding: 12px 24px; background: transparent; color: var(--fg); border: 1px solid var(--hairline); font-family: inherit; font-size: 14px; cursor: pointer;">Back to Terminal</button></div>';
      document.getElementById("back").addEventListener("click", function() {
        location.reload();
      });
    }

    async function showAdminPanel() {
      const res = await fetch('/api/admin/users', {
        headers: { 'Authorization': 'Bearer ' + authToken }
      });
      const users = await res.json();
      document.body.innerHTML = '<div id="admin-panel"><h2>Admin Panel</h2><div class="user-list"><h3>Users</h3>' + users.map(function(u) { return '<div class="user-item"><span>' + u.username + (u.isAdmin ? ' (Admin)' : '') + '</span>' + (!u.isAdmin ? '<button class="delete-btn" data-username="' + u.username + '">Delete</button>' : '') + '</div>'; }).join('') + '</div><div class="add-user-form"><h3>Add New User</h3><input type="text" id="new-username" placeholder="Username"><input type="password" id="new-password" placeholder="Temporary Password"><button id="add-user-btn">Add User</button></div><button id="back-admin" style="margin-top: 30px; padding: 12px 24px; background: transparent; color: var(--fg); border: 1px solid var(--hairline); cursor: pointer;">Back to Terminal</button></div>';
      document.getElementById("back-admin").addEventListener("click", function() {
        location.reload();
      });
      document.getElementById("add-user-btn").addEventListener("click", async function() {
        const username = document.getElementById("new-username").value;
        const password = document.getElementById("new-password").value;
        const res = await fetch('/api/admin/users', {
          method: 'POST',
          headers: {
            'Authorization': 'Bearer ' + authToken,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ username: username, password: password })
        });
        if (res.ok) {
          alert('User ' + username + ' created with password: ' + password);
          showAdminPanel();
        } else {
          alert('Failed to create user');
        }
      });
      document.querySelectorAll('.delete-btn').forEach(function(btn) {
        btn.addEventListener('click', async function() {
          const username = btn.dataset.username;
          if (confirm('Delete user ' + username + '?')) {
            await fetch('/api/admin/users/' + username, {
              method: 'DELETE',
              headers: { 'Authorization': 'Bearer ' + authToken }
            });
            showAdminPanel();
          }
        });
      });
    }

    input.addEventListener("keydown", function(e) {
      if (e.key === "Enter") {
        const text = input.value.trim();
        if (!text) return;
        const userDiv = document.createElement("div");
        userDiv.className = "entry";
        userDiv.textContent = text;
        timeline.insertBefore(userDiv, timeline.firstChild);
        const guardianDiv = document.createElement("div");
        guardianDiv.className = "entry";
        guardianDiv.textContent = "Noted. We'll watch for patterns.";
        timeline.insertBefore(guardianDiv, timeline.firstChild);
        input.value = "";
        fetch("/log", {
          method: "POST",
          headers: {
            'Authorization': 'Bearer ' + authToken,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ text: text })
        });
      }
    });

    checkAuth().then(function(authenticated) {
      if (authenticated) {
        showApp();
      }
    }).catch(function(err) {
      console.error('Startup auth check failed:', err);
    });
  </script>
</body>
</html>
  `);
});

app.get("/logs", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM logs WHERE username = $1 ORDER BY ts DESC',
      [req.user]
    );
    const logs = result.rows.map(row => ({
      ts: row.ts.toISOString(),
      user: row.username,
      role: row.role,
      text: row.text,
      file: row.file_name ? {
        name: row.file_name,
        original: row.file_original,
        type: row.file_type
      } : null,
      aiAnalysis: row.ai_analysis
    }));
    res.json(logs);
  } catch (err) {
    console.error('Get logs error:', err);
    res.status(500).json({ error: 'Failed to get logs' });
  }
});

app.post("/log", requireAuth, async (req, res) => {
  const text = (req.body && typeof req.body.text === "string") ? req.body.text.trim() : "";
  if (!text) return res.status(400).json({ ok: false });
  
  const ts = new Date();
  
  try {
    await pool.query(
      'INSERT INTO logs (ts, username, role, text) VALUES ($1, $2, $3, $4)',
      [ts, req.user, 'user', text]
    );
    
    await pool.query(
      'INSERT INTO logs (ts, username, role, text) VALUES ($1, $2, $3, $4)',
      [ts, req.user, 'guardian', "Noted. We'll watch for patterns."]
    );
    
    res.json({ ok: true });
  } catch (err) {
    console.error('Log entry error:', err);
    res.status(500).json({ error: 'Failed to log entry' });
  }
});

app.post("/upload", requireAuth, upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ ok: false });
  
  const ts = new Date();
  const filePath = path.join(UPLOAD_DIR, req.file.filename);
  const fileType = req.file.mimetype.startsWith("image/") ? "image" : "file";
  let analysisResult = null;
  let logText = req.body.text || "File uploaded";
  
  if (fileType === "image") {
    analysisResult = await analyzeImage(filePath);
    if (analysisResult.type === 'stool' && analysisResult.bristolScale) {
      logText = 'Stool logged - ' + analysisResult.bristolScale.description;
    } else {
      logText = analysisResult.analysis || "Photo uploaded";
    }
  }
  
  try {
    await pool.query(
      'INSERT INTO logs (ts, username, role, text, file_name, file_original, file_type, ai_analysis) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
      [ts, req.user, 'user', logText, req.file.filename, req.file.originalname, fileType, JSON.stringify(analysisResult)]
    );
    
    await pool.query(
      'INSERT INTO logs (ts, username, role, text) VALUES ($1, $2, $3, $4)',
      [ts, req.user, 'guardian', "Noted. We'll watch for patterns."]
    );
    
    res.json({ ok: true });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'Failed to upload file' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 UCell Terminal running at http://localhost:${PORT}`);
  console.log('👤 Default admin: james / ucell2024');
});
