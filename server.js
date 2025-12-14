const express = require("express");
const fs = require("fs");
const path = require("path");
const multer = require("multer");

const app = express();
app.use(express.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

const DATA_FILE = path.join(__dirname, "ucell_log.json");
const UPLOAD_DIR = path.join(__dirname, "uploads");
const VISION_API_KEY = "AIzaSyAlU7VoOIFnQ9CNQvIY3fgrAsRK_JJ4xeI";

// Ensure upload directory exists
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR);
}

// Configure file upload
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

function readLogs() {
  try {
    if (!fs.existsSync(DATA_FILE)) {
      fs.writeFileSync(DATA_FILE, "[]", "utf8");
      return [];
    }
    const raw = fs.readFileSync(DATA_FILE, "utf8");
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeLogs(logs) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(logs, null, 2), "utf8");
}

// Analyze image with Google Vision API
async function analyzeImage(imagePath) {
  try {
    const imageBuffer = fs.readFileSync(imagePath);
    const base64Image = imageBuffer.toString('base64');

    // Call Google Vision API
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
              { type: 'OBJECT_LOCALIZATION', maxResults: 10 }
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
    
    // Extract detected items
    const detectedLabels = labels.map(l => l.description.toLowerCase());
    const detectedObjects = objects.map(o => o.name.toLowerCase());
    const allDetected = [...detectedLabels, ...detectedObjects];

    // Determine if it's food or stool
    const foodKeywords = ['food', 'dish', 'meal', 'cuisine', 'salad', 'sandwich', 'burger', 
                          'pizza', 'pasta', 'rice', 'vegetable', 'fruit', 'meat', 'plate',
                          'bowl', 'sushi', 'burrito', 'soup', 'breakfast', 'lunch', 'dinner'];
    
    const stoolKeywords = ['toilet', 'bathroom', 'stool', 'feces', 'bowl'];

    const isFood = allDetected.some(item => foodKeywords.some(kw => item.includes(kw)));
    const isStool = allDetected.some(item => stoolKeywords.some(kw => item.includes(kw)));

    if (isFood) {
      return analyzeFoodImage(allDetected, labels);
    } else if (isStool) {
      return analyzeStoolImage(allDetected);
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
  // Identify food type
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

  // Estimate nutrition (rough estimates based on typical servings)
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

function analyzeStoolImage(detected) {
  // Basic stool analysis (Bristol scale estimation would require more sophisticated AI)
  return {
    type: 'stool',
    analysis: 'Stool photo logged. Review manually for Bristol scale classification.'
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

    body {
      min-height: 100vh;
      padding: 12px;
    }

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

    #upload-menu.active {
      display: flex;
    }

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

    .hidden {
      display: none;
    }
  </style>
</head>
<body>

  <div id="input-container">
    <input
      id="input"
      autofocus
      autocomplete="off"
      autocapitalize="off"
      autocorrect="off"
      spellcheck="false"
      placeholder="type and press enter"
    />
    <button id="add-btn">+</button>
  </div>

  <div id="upload-menu">
    <button class="upload-option" id="photo-btn">📷 Photo</button>
    <button class="upload-option" id="file-btn">📄 File</button>
  </div>

  <input type="file" id="photo-input" accept="image/*" capture="environment" class="hidden">
  <input type="file" id="file-input" accept=".pdf,.doc,.docx,.txt" class="hidden">

  <div id="timeline"></div>
  <div id="brand">UCell</div>

  <script>
    const input = document.getElementById("input");
    const timeline = document.getElementById("timeline");
    const brand = document.getElementById("brand");
    const addBtn = document.getElementById("add-btn");
    const uploadMenu = document.getElementById("upload-menu");
    const photoBtn = document.getElementById("photo-btn");
    const fileBtn = document.getElementById("file-btn");
    const photoInput = document.getElementById("photo-input");
    const fileInput = document.getElementById("file-input");

    function renderEntry(entry) {
      const div = document.createElement("div");
      div.className = "entry";
      
      let html = entry.text || "";
      
      if (entry.file) {
        if (entry.file.type === "image") {
          html += \`<br><img src="/uploads/\${entry.file.name}" alt="uploaded image">\`;
        } else {
          html += \`<br><a href="/uploads/\${entry.file.name}" target="_blank">📎 \${entry.file.original}</a>\`;
        }
      }
      
      div.innerHTML = html;
      return div;
    }

    async function loadHistory() {
      try {
        const res = await fetch("/logs");
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

    loadHistory();

    // Toggle upload menu
    addBtn.addEventListener("click", () => {
      uploadMenu.classList.toggle("active");
    });

    // Close menu when clicking outside
    document.addEventListener("click", (e) => {
      if (!addBtn.contains(e.target) && !uploadMenu.contains(e.target)) {
        uploadMenu.classList.remove("active");
      }
    });

    // Photo upload
    photoBtn.addEventListener("click", () => {
      photoInput.click();
      uploadMenu.classList.remove("active");
    });

    photoInput.addEventListener("change", async (e) => {
      const file = e.target.files[0];
      if (!file) return;

      // Show "analyzing..." message
      const analyzingDiv = document.createElement("div");
      analyzingDiv.className = "entry analyzing";
      analyzingDiv.textContent = "📷 Analyzing photo...";
      timeline.insertBefore(analyzingDiv, timeline.firstChild);

      const formData = new FormData();
      formData.append("file", file);

      try {
        const res = await fetch("/upload", {
          method: "POST",
          body: formData
        });
        
        if (res.ok) {
          loadHistory();
        }
      } catch (err) {
        console.error("Upload failed:", err);
        analyzingDiv.textContent = "Upload failed";
      }

      photoInput.value = "";
    });

    // File upload
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

    // Hidden dashboard portal
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

    async function openDashboard() {
      const res = await fetch("/logs");
      const logs = await res.json();
      
      const userLogs = logs.filter(e => e.role === "user");
      const days = new Set(userLogs.map(e => e.ts.split("T")[0])).size;
      
      document.body.innerHTML = \`
        <div style="padding: 20px; text-align: center;">
          <div style="font-size: 48px; margin-bottom: 20px; color: var(--fg);">\${userLogs.length}</div>
          <div style="font-size: 14px; color: var(--muted); margin-bottom: 10px;">entries logged</div>
          <div style="font-size: 14px; color: var(--muted); margin-bottom: 40px;">active for \${days} days</div>
          <button id="back" style="padding: 12px 24px; background: transparent; color: var(--fg); border: 1px solid var(--hairline); font-family: inherit; font-size: 14px; cursor: pointer;">Back to Terminal</button>
        </div>
      \`;
      
      document.getElementById("back").addEventListener("click", () => {
        location.reload();
      });
    }

    // Text input
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
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text })
        });
      }
    });
  </script>

</body>
</html>

  `);
});

app.get("/logs", (req, res) => {
  res.json(readLogs());
});

app.post("/log", (req, res) => {
  const text =
    (req.body && typeof req.body.text === "string")
      ? req.body.text.trim()
      : "";

  if (!text) return res.status(400).json({ ok: false });

  const logs = readLogs();
  const ts = new Date().toISOString();

  logs.push({
    ts,
    role: "user",
    text
  });

  logs.push({
    ts,
    role: "guardian",
    text: "Noted. We'll watch for patterns."
  });

  writeLogs(logs);

  res.json({ ok: true });
});

app.post("/upload", upload.single("file"), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ ok: false });
  }

  const logs = readLogs();
  const ts = new Date().toISOString();
  const filePath = path.join(UPLOAD_DIR, req.file.filename);
  const fileType = req.file.mimetype.startsWith("image/") ? "image" : "file";

  let analysisResult = null;
  let logText = req.body.text || "File uploaded";

  // Analyze if it's an image
  if (fileType === "image") {
    analysisResult = await analyzeImage(filePath);
    logText = analysisResult.analysis || "Photo uploaded";
  }

  logs.push({
    ts,
    role: "user",
    text: logText,
    file: {
      name: req.file.filename,
      original: req.file.originalname,
      type: fileType
    },
    aiAnalysis: analysisResult
  });

  logs.push({
    ts,
    role: "guardian",
    text: "Noted. We'll watch for patterns."
  });

  writeLogs(logs);

  res.json({ ok: true });
});

app.listen(3000, () => {
  console.log("running at http://localhost:3000");
});