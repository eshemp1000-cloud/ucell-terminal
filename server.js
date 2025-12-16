const express = require("express");
const fs = require("fs");
const path = require("path");
const multer = require("multer");
const crypto = require("crypto");

const app = express();
app.use(express.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

const DATA_FILE = path.join(__dirname, "ucell_log.json");
const USERS_FILE = path.join(__dirname, "users.json");
const SESSIONS_FILE = path.join(__dirname, "sessions.json");
const UPLOAD_DIR = path.join(__dirname, "uploads");
const VISION_API_KEY = "AIzaSyAlU7VoOIFnQ9CNQvIY3fgrAsRK_JJ4xeI";

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

function readJSON(filepath, defaultValue = []) {
  try {
    if (!fs.existsSync(filepath)) {
      fs.writeFileSync(filepath, JSON.stringify(defaultValue), "utf8");
      return defaultValue;
    }
    const raw = fs.readFileSync(filepath, "utf8");
    const parsed = JSON.parse(raw);
    return Array.isArray(defaultValue) ? (Array.isArray(parsed) ? parsed : defaultValue) : parsed;
  } catch {
    return defaultValue;
  }
}

function writeJSON(filepath, data) {
  fs.writeFileSync(filepath, JSON.stringify(data, null, 2), "utf8");
}

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

function getSession(token) {
  const sessions = readJSON(SESSIONS_FILE, {});
  return sessions[token] || null;
}

function createSession(username) {
  const token = generateSessionToken();
  const sessions = readJSON(SESSIONS_FILE, {});
  sessions[token] = {
    username,
    createdAt: new Date().toISOString()
  };
  writeJSON(SESSIONS_FILE, sessions);
  return token;
}

function deleteSession(token) {
  const sessions = readJSON(SESSIONS_FILE, {});
  delete sessions[token];
  writeJSON(SESSIONS_FILE, sessions);
}
function requireAuth(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  const session = getSession(token);
  
  if (!session) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  req.user = session.username;
  next();
}

function requireAdmin(req, res, next) {
  const users = readJSON(USERS_FILE, {});
  const user = users[req.user];
  
  if (!user || !user.isAdmin) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  
  next();
}

function initializeUsers() {
  const users = readJSON(USERS_FILE, {});
  if (Object.keys(users).length === 0) {
    users['james'] = {
      password: hashPassword('ucell2024'),
      isAdmin: true,
      createdAt: new Date().toISOString()
    };
    writeJSON(USERS_FILE, users);
    console.log('Created default admin user: james / ucell2024');
  }
}

initializeUsers();

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  
  const users = readJSON(USERS_FILE, {});
  const user = users[username];
  
  if (!user || user.password !== hashPassword(password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  const token = createSession(username);
  
  res.json({
    token,
    username,
    isAdmin: user.isAdmin || false
  });
});

app.post("/api/logout", requireAuth, (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  deleteSession(token);
  res.json({ ok: true });
});

app.get("/api/me", requireAuth, (req, res) => {
  const users = readJSON(USERS_FILE, {});
  const user = users[req.user];
  
  res.json({
    username: req.user,
    isAdmin: user.isAdmin || false
  });
});

app.get("/api/admin/users", requireAuth, requireAdmin, (req, res) => {
  const users = readJSON(USERS_FILE, {});
  const userList = Object.keys(users).map(username => ({
    username,
    isAdmin: users[username].isAdmin || false,
    createdAt: users[username].createdAt
  }));
  res.json(userList);
});

app.post("/api/admin/users", requireAuth, requireAdmin, (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  
  const users = readJSON(USERS_FILE, {});
  
  if (users[username]) {
    return res.status(400).json({ error: 'Username already exists' });
  }
  
  users[username] = {
    password: hashPassword(password),
    isAdmin: false,
    createdAt: new Date().toISOString()
  };
  
  writeJSON(USERS_FILE, users);
  
  res.json({ ok: true, username });
});

app.delete("/api/admin/users/:username", requireAuth, requireAdmin, (req, res) => {
  const { username } = req.params;
  
  if (username === req.user) {
    return res.status(400).json({ error: 'Cannot delete your own account' });
  }
  
  const users = readJSON(USERS_FILE, {});
  delete users[username];
  writeJSON(USERS_FILE, users);
  
  res.json({ ok: true });
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

    // Check for brown/tan colors (strong indicator of stool)
    const hasBrownColor = colors.some(color => {
      const r = color.color.red || 0;
      const g = color.color.green || 0;
      const b = color.color.blue || 0;
      // Brown/tan color range
      return (r > 100 && r < 200 && g > 70 && g < 150 && b > 30 && b < 100);
    });

    // Enhanced stool detection keywords
    const stoolKeywords = [
      'toilet', 'bathroom', 'feces', 'excrement', 'waste',
      'defecation', 'bowel', 'restroom', 'lavatory', 'water closet',
      'porcelain', 'ceramic', 'flush', 'commode'
    ];

    const foodKeywords = [
      'food', 'dish', 'meal', 'cuisine', 'salad', 'sandwich', 'burger', 
      'pizza', 'pasta', 'rice', 'vegetable', 'fruit', 'meat', 'plate',
      'sushi', 'burrito', 'soup', 'breakfast', 'lunch', 'dinner', 'snack',
      'dessert', 'bread', 'cheese', 'chicken', 'beef', 'pork', 'fish'
    ];

    // Check for stool FIRST (before food)
    const stoolMatches = allDetected.filter(item => 
      stoolKeywords.some(kw => item.includes(kw))
    );

    // If we have toilet/bathroom keywords OR brown color, it's stool
    if (stoolMatches.length > 0 || hasBrownColor) {
      return analyzeStoolImage(allDetected);
    }

    // Then check for food
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

async function analyzeStoolImage(detected) {
  // Bristol Stool Scale Classification
  let bristolType = null;
  let bristolDescription = '';
  
  // Analyze consistency from detected labels
  const labelText = detected.join(' ').toLowerCase();
  
  // Bristol Scale Type determination based on keywords
  if (labelText.includes('hard') || labelText.includes('lumpy') || labelText.includes('pellet')) {
    bristolType = labelText.includes('separate') ? 1 : 2;
    bristolDescription = bristolType === 1 
      ? 'Type 1: Separate hard lumps (severe constipation)'
      : 'Type 2: Lumpy and sausage-like (mild constipation)';
  } else if (labelText.includes('crack') || (labelText.includes('sausage') && labelText.includes('surface'))) {
    bristolType = 3;
    bristolDescription = 'Type 3: Sausage-shaped with cracks (normal)';
  } else if (labelText.includes('smooth') && labelText.includes('soft')) {
    bristolType = 4;
    bristolDescription = 'Type 4: Smooth and soft (ideal/normal)';
  } else if (labelText.includes('soft') || labelText.includes('blob') || labelText.includes('fluffy')) {
    bristolType = 5;
    bristolDescription = 'Type 5: Soft blobs with clear edges (mild diarrhea)';
  } else if (labelText.includes('mushy') || labelText.includes('ragged') || labelText.includes('porridge')) {
    bristolType = 6;
    bristolDescription = 'Type 6: Mushy with ragged edges (diarrhea)';
  } else if (labelText.includes('liquid') || labelText.includes('watery') || labelText.includes('diarrhea')) {
    bristolType = 7;
    bristolDescription = 'Type 7: Entirely liquid (severe diarrhea)';
  } else {
    // Default to Type 4 if unclear
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
    <button id="login-btn">Login</button>
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
      } catch {}
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
      } catch {
        loginError.textContent = 'Login failed';
      }
    }

    function showApp() {
      loginScreen.style.display = 'none';
      app.style.display = 'block';
      input.focus();
      loadHistory();
    }

    loginBtn.addEventListener('click', login);
    document.getElementById('login-password').addEventListener('keydown', e => {
      if (e.key === 'Enter') login();
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
      } catch {}
    }

    addBtn.addEventListener("click", () => {
      uploadMenu.classList.toggle("active");
    });

    document.addEventListener("click", (e) => {
      if (!addBtn.contains(e.target) && !uploadMenu.contains(e.target)) {
        uploadMenu.classList.remove("active");
      }
    });

    photoBtn.addEventListener("click", () => {
      photoInput.click();
      uploadMenu.classList.remove("active");
    });

    photoInput.addEventListener("change", async (e) => {
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

    fileBtn.addEventListener("click", () => {
      fileInput.click();
      uploadMenu.classList.remove("active");
    });

    fileInput.addEventListener("change", async (e) => {
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
    brand.addEventListener("click", () => {
      tapCount++;
      if (tapCount === 1) {
        tapTimer = setTimeout(() => { tapCount = 0; }, 1000);
      }
      if (tapCount === 3) {
        clearTimeout(tapTimer);
        tapCount = 0;
        openDashboard();
      }
    });
// Medical History button
const medicalHistoryBtn = document.getElementById('medical-history-btn');
if (medicalHistoryBtn) {
  medicalHistoryBtn.addEventListener('click', async () => {
    try {
      const res = await fetch('/medical-records', {
        headers: { 'Authorization': 'Bearer ' + authToken }
      });
      const records = await res.json();
      
      if (!records || records.length === 0) {
        alert('No medical records found');
        return;
      }
      
      // Build HTML
      let html = '<div style="padding: 20px; max-width: 800px; margin: 0 auto;">';
      html += '<h2 style="color: var(--fg); margin-bottom: 30px;">Medical History</h2>';
      
      records.forEach(record => {
        html += '<div style="margin-bottom: 40px; padding: 20px; border: 1px solid var(--hairline); border-radius: 8px;">';
        html += '<h3 style="color: var(--fg); margin-bottom: 15px;">' + record.filename + '</h3>';
        html += '<div style="color: var(--fg); line-height: 1.6; white-space: pre-wrap;">' + record.summary + '</div>';
        html += '</div>';
      });
      
      html += '<button id="back-to-terminal" style="padding: 12px 24px; background: transparent; color: var(--fg); border: 1px solid var(--hairline); font-family: inherit; cursor: pointer; margin-top: 20px;">Back to Terminal</button>';
      html += '</div>';
      
      document.body.innerHTML = html;
      
      document.getElementById('back-to-terminal').addEventListener('click', () => {
        location.reload();
      });
      
    } catch (err) {
      alert('Failed to load medical records');
    }
  });
}
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
      const userLogs = logs.filter(e => e.role === "user");
      const days = new Set(userLogs.map(e => e.ts.split("T")[0])).size;
     document.body.innerHTML = '<div style="padding: 20px; text-align: center;"><div style="font-size: 48px; margin-bottom: 20px; color: var(--fg);">' + userLogs.length + '</div><div style="font-size: 14px; color: var(--muted); margin-bottom: 10px;">entries logged</div><div style="font-size: 14px; color: var(--muted); margin-bottom: 40px;">active for ' + days + ' days</div><button id="medical-history-dashboard" style="margin-bottom: 15px; padding: 12px 24px; background: transparent; color: var(--fg); border: 1px solid var(--hairline); font-family: inherit; font-size: 14px; cursor: pointer; display: block; margin-left: auto; margin-right: auto;">Medical History</button><button id="back" style="padding: 12px 24px; background: transparent; color: var(--fg); border: 1px solid var(--hairline); font-family: inherit; font-size: 14px; cursor: pointer;">Back to Terminal</button></div>';
      document.getElementById("back").addEventListener("click", () => {
        location.reload();
      });
      document.getElementById("medical-history-dashboard").addEventListener("click", async () => {
      const res = await fetch('/medical-records', {
        headers: { 'Authorization': 'Bearer ' + authToken }
      });
      const records = await res.json();
      
      let html = '<div style="padding: 20px; max-width: 800px; margin: 0 auto;">';
      html += '<h2 style="color: var(--fg); margin-bottom: 30px;">Medical History</h2>';
      
      records.forEach(record => {
        html += '<div style="margin-bottom: 40px; padding: 20px; border: 1px solid var(--hairline); border-radius: 8px;">';
        html += '<h3 style="color: var(--fg); margin-bottom: 15px;">' + record.filename + '</h3>';
        html += '<div style="color: var(--fg); line-height: 1.6; white-space: pre-wrap;">' + record.summary + '</div>';
        html += '</div>';
      });
      
      html += '<button id="back-to-dashboard" style="padding: 12px 24px; background: transparent; color: var(--fg); border: 1px solid var(--hairline); cursor: pointer;">Back</button></div>';
      
      document.body.innerHTML = html;
      document.getElementById('back-to-dashboard').addEventListener('click', () => location.reload());
    });
    }

    async function showAdminPanel() {
      const res = await fetch('/api/admin/users', {
        headers: { 'Authorization': 'Bearer ' + authToken }
      });
      const users = await res.json();
      document.body.innerHTML = '<div id="admin-panel"><h2>Admin Panel</h2><div class="user-list"><h3>Users</h3>' + users.map(u => '<div class="user-item"><span>' + u.username + (u.isAdmin ? ' (Admin)' : '') + '</span>' + (!u.isAdmin ? '<button class="delete-btn" data-username="' + u.username + '">Delete</button>' : '') + '</div>').join('') + '</div><div class="add-user-form"><h3>Add New User</h3><input type="text" id="new-username" placeholder="Username"><input type="password" id="new-password" placeholder="Temporary Password"><button id="add-user-btn">Add User</button></div><button id="back-admin" style="margin-top: 30px; padding: 12px 24px; background: transparent; color: var(--fg); border: 1px solid var(--hairline); cursor: pointer;">Back to Terminal</button></div>';
      document.getElementById("back-admin").addEventListener("click", () => {
        location.reload();
      });
      document.getElementById("add-user-btn").addEventListener("click", async () => {
        const username = document.getElementById("new-username").value;
        const password = document.getElementById("new-password").value;
        const res = await fetch('/api/admin/users', {
          method: 'POST',
          headers: {
            'Authorization': 'Bearer ' + authToken,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ username, password })
        });
        if (res.ok) {
          alert('User ' + username + ' created with password: ' + password);
          showAdminPanel();
        } else {
          alert('Failed to create user');
        }
      });
      document.querySelectorAll('.delete-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
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

    input.addEventListener("keydown", e => {
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
          body: JSON.stringify({ text })
        });
      }
    });

    checkAuth().then(authenticated => {
      if (authenticated) {
        showApp();
      }
    });
  </script>
</body>
</html>
  `);
});

app.get("/logs", requireAuth, (req, res) => {
  const allLogs = readJSON(DATA_FILE);
  const userLogs = allLogs.filter(log => log.user === req.user);
  res.json(userLogs);
});
app.get("/medical-records", requireAuth, (req, res) => {
  const MEDICAL_RECORDS_FILE = path.join(__dirname, 'medical_records.json');
  const records = readJSON(MEDICAL_RECORDS_FILE, []);
  res.json(records);
});

app.post("/log", requireAuth, (req, res) => {
  const text = (req.body && typeof req.body.text === "string") ? req.body.text.trim() : "";
  if (!text) return res.status(400).json({ ok: false });
  const allLogs = readJSON(DATA_FILE);
  const ts = new Date().toISOString();
  allLogs.push({ ts, user: req.user, role: "user", text });
  allLogs.push({ ts, user: req.user, role: "guardian", text: "Noted. We'll watch for patterns." });
  writeJSON(DATA_FILE, allLogs);
  res.json({ ok: true });
});

app.post("/upload", requireAuth, upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ ok: false });
  const allLogs = readJSON(DATA_FILE);
  const ts = new Date().toISOString();
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
  allLogs.push({
    ts, user: req.user, role: "user", text: logText,
    file: { name: req.file.filename, original: req.file.originalname, type: fileType },
    aiAnalysis: analysisResult
  });
  allLogs.push({ ts, user: req.user, role: "guardian", text: "Noted. We'll watch for patterns." });
  writeJSON(DATA_FILE, allLogs);
  res.json({ ok: true });
});
// Medical record upload endpoint
app.post("/upload-medical-record", requireAuth, upload.single("file"), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  if (req.file.mimetype !== 'application/pdf') {
    return res.status(400).json({ error: 'Only PDF files are supported' });
  }

  try {
    const pdfParse = require('pdf-parse');
    const pdfBuffer = fs.readFileSync(req.file.path);
    const pdfData = await pdfParse(pdfBuffer);
    const extractedText = pdfData.text;

    // Parse with Claude API
    const parseResponse = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY || 'YOUR_KEY_HERE',
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 2000,
        messages: [{
          role: 'user',
          content: `Parse this medical document and extract key information. Return ONLY a JSON object with these fields:
          
{
  "document_type": "lab_result" | "imaging_report" | "clinical_note" | "discharge_summary" | "other",
  "date_of_service": "YYYY-MM-DD",
  "provider": "provider name",
  "key_findings": "brief summary",
  "metrics": {} // any numeric values like lab results
}

Document text:
${extractedText}`
        }]
      })
    });

    const parseData = await parseResponse.json();
    let parsedRecord = {};
    
    try {
      const responseText = parseData.content[0].text;
      parsedRecord = JSON.parse(responseText);
    } catch {
      parsedRecord = {
        document_type: 'other',
        date_of_service: new Date().toISOString().split('T')[0],
        provider: 'Unknown',
        key_findings: 'Could not parse',
        metrics: {}
      };
    }

    // Store in medical_records.json
    const MEDICAL_RECORDS_FILE = path.join(__dirname, 'medical_records.json');
    const allRecords = readJSON(MEDICAL_RECORDS_FILE, []);
    
    allRecords.push({
      id: Date.now().toString(),
      user: req.user,
      filename: req.file.originalname,
      filepath: req.file.path,
      uploaded_at: new Date().toISOString(),
      parsed_data: parsedRecord,
      raw_text: extractedText.substring(0, 5000) // Store first 5000 chars
    });

    writeJSON(MEDICAL_RECORDS_FILE, allRecords);

    res.json({ 
      ok: true, 
      message: 'Medical record uploaded and parsed',
      parsed: parsedRecord
    });

  } catch (error) {
    console.error('Medical record processing error:', error);
    res.status(500).json({ error: 'Failed to process medical record' });
  }
});
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`UCell Terminal running at http://localhost:${PORT}`);
  console.log('Default admin: james / ucell2024');
});
