require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const { Low } = require("lowdb");
const { JSONFile } = require("lowdb/node");
const { nanoid } = require("nanoid");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");
const multer = require("multer");
const { GoogleGenAI } = require("@google/genai");

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

const app = express();
app.use(cors());
app.use(bodyParser.json());

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_jwt_secret";

// ---------------- Utils ----------------
function normalizePhone(phone) {
  if (!phone) return phone;
  let s = String(phone).replace(/\s+/g, "").replace(/[-()]/g, "");
  if (s.startsWith("+")) return s;
  const onlyDigits = s.replace(/\D/g, "");
  if (onlyDigits.length === 10) return "+91" + onlyDigits;
  if (s.startsWith("00")) return "+" + s.slice(2);
  return "+" + onlyDigits;
}

function createToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: "30d" });
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "No token" });
  const token = header.replace("Bearer ", "");
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// ---------------- DB ----------------
const DB_FILE = path.join(__dirname, "db.json");
if (!fs.existsSync(DB_FILE)) {
  fs.writeFileSync(
    DB_FILE,
    JSON.stringify(
      {
        users: [],
        food_checks: [],
        meal_logs: [],
        symptom_logs: [],
        monthly_reports: [],
        gut_logs: [],
        otps: {},
      },
      null,
      2
    )
  );
}

const adapter = new JSONFile(DB_FILE);
const db = new Low(adapter, {});
(async () => {
  await db.read();
  db.data ||= {
    users: [],
    food_checks: [],
    meal_logs: [],
    symptom_logs: [],
    monthly_reports: [],
    gut_logs: [],
    otps: {},
  };
  await db.write();
})();

// ---------------- Upload ----------------
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
const upload = multer({ dest: uploadDir });

// ---------------- Routes ----------------
app.get("/", (_, res) => res.send("Healthies backend running"));

// ===== AUTH =====

// Send OTP
app.post("/auth/send-otp", async (req, res) => {
  let { phone } = req.body;
  if (!phone) return res.status(400).json({ error: "phone required" });

  phone = normalizePhone(phone);
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const now = Date.now();
  const TTL = 10 * 60 * 1000;

  await db.read();
  db.data.otps[phone] = { code, createdAt: now, expiresAt: now + TTL };
  await db.write();

  console.log(`DEV OTP for ${phone}: ${code}`);
  res.json({ success: true, phone, devCode: code });
});

// Verify OTP → only verifies phone, does NOT login
app.post("/auth/verify-otp", async (req, res) => {
  let { phone, code } = req.body;
  if (!phone || !code)
    return res.status(400).json({ error: "phone & code required" });

  phone = normalizePhone(phone);
  await db.read();
  const entry = db.data.otps[phone];
  if (!entry) return res.status(400).json({ error: "invalid code" });
  if (Date.now() > entry.expiresAt)
    return res.status(400).json({ error: "code expired" });
  if (entry.code !== String(code).trim())
    return res.status(400).json({ error: "invalid code" });

  delete db.data.otps[phone];

  let user = db.data.users.find((u) => u.phone === phone);
  if (!user) {
    user = {
      id: nanoid(),
      phone,
      username: null,
      password: null,
      createdAt: new Date().toISOString(),
      disease: null,
    };
    db.data.users.push(user);
  }
  await db.write();

  res.json({ success: true, user });
});

// Login / Register username + password
app.post("/auth/login", async (req, res) => {
  try {
    let { phone, username, password } = req.body;
    if (!phone || !username || !password) {
      return res
        .status(400)
        .json({ error: "phone, username and password required" });
    }

    phone = normalizePhone(phone);
    await db.read();
    const user = db.data.users.find((u) => u.phone === phone);

    if (!user) return res.status(404).json({ error: "User not found" });

    // First time → save creds
    if (!user.username || !user.password) {
      user.username = username;
      user.password = password;
      user.updatedAt = new Date().toISOString();
      await db.write();
    }

    if (user.username !== username || user.password !== password) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const token = createToken(user.id);
    res.json({ token, user });
  } catch (err) {
    console.error("Login error:", err.message);
    res.status(500).json({ error: "Login failed" });
  }
});

//================================ USER ==============
app.get("/user/me", authMiddleware, async (req, res) => {
  await db.read();
  const user = db.data.users.find((u) => u.id === req.userId);
  if (!user) return res.status(404).json({ error: "user not found" });
  res.json({ user });
});

app.put("/user/me", authMiddleware, async (req, res) => {
  const updates = req.body;
  await db.read();
  const idx = db.data.users.findIndex((u) => u.id === req.userId);
  if (idx === -1) return res.status(404).json({ error: "user not found" });

  db.data.users[idx] = {
    ...db.data.users[idx],
    ...updates,
    updatedAt: new Date().toISOString(),
  };
  await db.write();

  res.json({ user: db.data.users[idx] });
});
 

// ===== FOOD CHECK (AI) =====
app.post("/food/check", authMiddleware, upload.single("image"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "Image required" });

    await db.read();
    const user = db.data.users.find(u => u.id === req.userId);
    const disease = user?.disease || "Ulcerative Colitis";

    const img = fs.readFileSync(req.file.path).toString("base64");

    const prompt = `Identify the food in this image. Is it safe for someone with ${disease}?
Return ONLY JSON: {"food":"","verdict":"Yes/No","explanation":"","alternatives":[]}`;

    const response = await ai.models.generateContent({
      model: "gemini-2.5-flash",
      contents: [{
        role: "user",
        parts: [
          { inlineData: { mimeType: req.file.mimetype, data: img } },
          { text: prompt }
        ],
      }],
      config: { responseMimeType: "application/json" }
    });

    const result = JSON.parse(response.text);

    db.data.food_checks.push({
      id: nanoid(),
      userId: req.userId,
      ...result,
      createdAt: new Date().toISOString(),
    });
    await db.write();

    fs.unlinkSync(req.file.path); 

    res.json(result);
  } catch (err) {
    console.error("Food AI error:", err.message);
    res.status(500).json({ error: "Analysis failed" });
  }
});


// ===== LOG MEAL =====
app.post("/meals/log", authMiddleware, async (req, res) => {
  try {
    const { foodName, recommended } = req.body;
    if (!foodName) {
      return res.status(400).json({ error: "foodName required" });
    }

    const now = new Date();
    const dateKey = now.toISOString().slice(0, 10);

    await db.read();

    db.data.meal_logs = db.data.meal_logs || [];

    db.data.meal_logs.push({
      id: nanoid(),
      userId: req.userId,
      foodName,
      recommended: !!recommended,
      dateKey, // ✅ important
      timestamp: now.toISOString(),
    });

    await db.write();

    console.log("🍽️ Meal logged:", foodName, dateKey);

    res.json({ success: true });
  } catch (err) {
    console.error("Meal log error:", err.message);
    res.status(500).json({ error: "Could not log meal" });
  }
});

// ===== TODAY AI REPORT =====
app.post("/reports/today/ai", authMiddleware, async (req, res) => {
  try {
    await db.read();
    const userId = req.userId;
    const todayKey = new Date().toISOString().slice(0, 10);

    const meals = db.data.meal_logs.filter(
      (m) =>
        m.userId === userId &&
        m.timestamp &&
        m.timestamp.startsWith(todayKey)
    );

    if (meals.length === 0) {
      return res.json({
        date: todayKey,
        summary: "No meals were logged today.",
        problemFoods: [],
        symptomInsight: "",
        recommendations: [],
        ai: true,
      });
    }
    const prompt = `
    You are a health assistant for a user with gut sensitivity (like ulcerative colitis).
    
    Foods eaten today:
    ${meals.map(m => `- ${m.foodName} (recommended: ${m.recommended})`).join("\n")}
    
    Analyze these foods and generate a detailed daily health report.
    
    Guidelines:
    - Summary should be 2-3 sentences describing overall diet quality and foods eaten.
    - problemFoods should list foods that may irritate the gut.
    - symptomInsight should briefly explain possible digestion effects today or tomorrow.
    - recommendations should be 2-3 short practical tips (what to eat more, avoid, hydration, timing).
    
    Return ONLY valid JSON in this format:
    {
      "summary": "",
      "problemFoods": [],
      "symptomInsight": "",
      "recommendations": []
    }
    `;

    const response = await ai.models.generateContent({
      model: "gemini-2.5-flash",
      contents: [{ role: "user", parts: [{ text: prompt }] }],
      config: { responseMimeType: "application/json" },
    });

    const parsed = JSON.parse(response.text);
    res.json({ date: todayKey, ai: true, ...parsed });
  } catch (err) {
    console.error("Today report error:", err.message);
    res.status(500).json({ error: "Today's AI report failed" });
  }
});
// ===== SAVE GUT FEEDBACK =====
app.post("/gut/feedback", authMiddleware, async (req, res) => {
  try {
    const { status } = req.body; // "good" or "bad"
    if (!status) return res.status(400).json({ error: "status required" });

    await db.read();

    // ✅ Ensure gut_logs exists
    if (!db.data.gut_logs) {
      db.data.gut_logs = [];
    }

    db.data.gut_logs.push({
      id: nanoid(),
      userId: req.userId,
      status,
      dateKey: new Date().toISOString().slice(0, 10),
      createdAt: new Date().toISOString(),
    });

    await db.write();

    res.json({ success: true });
  } catch (err) {
    console.error("Gut feedback save error:", err.message);
    res.status(500).json({ error: "Could not save gut feedback" });
  }
});

// ===== YESTERDAY FOLLOW-UP AI ADVICE =====
app.post("/reports/yesterday/followup", authMiddleware, async (req, res) => {
  try {
    const { status } = req.body; // "good" | "bad"
    if (!status) return res.status(400).json({ error: "status required" });

    await db.read();
    const userId = req.userId;

    const yesterdayKey = new Date(
      Date.now() - 24 * 60 * 60 * 1000
    ).toISOString().slice(0, 10);

    const meals = db.data.meal_logs.filter(
      (m) => m.userId === userId && m.dateKey === yesterdayKey
    );

    const foodsText =
      meals.length > 0
        ? meals.map((m) => `- ${m.foodName} (recommended: ${m.recommended})`).join("\n")
        : "No meals logged.";

    const prompt = `
User ate these foods yesterday:
${foodsText}

Today the user says their gut feels: ${status.toUpperCase()}.

If status is GOOD:
- Encourage them.
- Say which foods likely helped.
- Motivate to continue.

If status is BAD:
- Be empathetic.
- Point out possible problem foods.
- Suggest what to avoid and what to eat today.
- Give hydration/rest tips.

Write a short friendly response in 3-5 sentences.
Do NOT return JSON. Just plain text.
`;

    const response = await ai.models.generateContent({
      model: "gemini-2.5-flash",
      contents: [{ role: "user", parts: [{ text: prompt }] }],
    });

    const message = response.text?.trim() || "Thanks for your feedback. Take care!";

    res.json({ message });
  } catch (err) {
    console.error("Follow-up AI error:", err.message);
    res.status(500).json({ error: "AI follow-up failed" });
  }
});



// ===== YESTERDAY AI REPORT =====
app.post("/reports/yesterday/ai", authMiddleware, async (req, res) => {
  try {
    await db.read();
    const userId = req.userId;

    const d = new Date();
    d.setDate(d.getDate() - 1);
    const yesterdayKey = d.toISOString().slice(0, 10);

    const meals = db.data.meal_logs.filter(
      (m) =>
        m.userId === userId &&
        m.timestamp &&
        m.timestamp.startsWith(yesterdayKey)
    );

    if (meals.length === 0) {
      return res.json({
        date: yesterdayKey,
        summary: "No meals were logged yesterday.",
        problemFoods: [],
        symptomInsight: "",
        recommendations: [],
        ai: true,
      });
    }

    const prompt = `
Foods eaten yesterday:
${meals.map(m => `- ${m.foodName} (recommended: ${m.recommended})`).join("\n")}

Return ONLY JSON:
{
 "summary":"",
 "problemFoods":[],
 "symptomInsight":"",
 "recommendations":[]
}
`;

    const response = await ai.models.generateContent({
      model: "gemini-2.5-flash",
      contents: [{ role: "user", parts: [{ text: prompt }] }],
      config: { responseMimeType: "application/json" },
    });

    const parsed = JSON.parse(response.text);
    res.json({ date: yesterdayKey, ai: true, ...parsed });
  } catch (err) {
    console.error("Yesterday report error:", err.message);
    res.status(500).json({ error: "Yesterday AI report failed" });
  }
});

// ===== MONTHLY AI REPORT =====
app.post("/reports/monthly/ai", authMiddleware, async (req, res) => {
  try {
    const { month } = req.body; // "YYYY-MM"
    if (!month) return res.status(400).json({ error: "month required" });

    await db.read();
    const meals = db.data.meal_logs.filter(
      (m) => m.userId === req.userId && m.timestamp.startsWith(month)
    );

    if (meals.length === 0) {
      return res.json({
        month,
        summary: "No meals logged this month.",
        goodFoods: [],
        problemFoods: [],
        patterns: "",
        recommendations: [],
        explanation: "",
        ai: true,
      });
    }

    const prompt = `
Foods eaten this month:
${meals
  .map((m) => `- ${m.foodName} (recommended: ${m.recommended})`)
  .join("\n")}

Analyze gut health and return ONLY JSON in this format:
{
  "summary": "2-3 sentence overview of diet quality",
  "goodFoods": [{ "item": "", "recommended": true }],
  "problemFoods": [{ "item": "", "recommended": false }],
  "patterns": "Any repeating patterns you notice",
  "recommendations": ["2-3 actionable tips"],
  "explanation": "Short explanation of why these foods affect gut health"
}
`;

    const response = await ai.models.generateContent({
      model: "gemini-2.5-flash",
      contents: [{ role: "user", parts: [{ text: prompt }] }],
      config: { responseMimeType: "application/json" },
    });

    const parsed = JSON.parse(response.text);
    res.json({ month, ai: true, ...parsed });
  } catch (err) {
    console.error("Monthly report error:", err.message);
    res.status(500).json({ error: "Monthly AI report failed" });
  }
});
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Backend started on http://localhost:${PORT}`);
});
