// University Result Portal - Express + MongoDB (Mongoose)
const path = require("path");
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { User, Marks, SUBJECTS } = require("./models");

const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/university_portal";
const SECRET = process.env.JWT_SECRET || "change-this-secret-in-production";
const PORT = process.env.PORT || 3000;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

const app = express();
app.use(express.json({ limit: "10kb" }));
app.use(express.static(path.join(__dirname, "public")));

// Only accept strings (blocks NoSQL injection like {"$ne": ""})
const str = (v) => (typeof v === "string" ? v : "");
const wrap = (fn) => (req, res, next) => fn(req, res, next).catch(next);
const publicUser = (u) => ({ name: u.name, email: u.email, role: u.role, studentId: u.studentId, dept: u.dept, sem: u.sem, degree: u.degree });

// ---------- Authentication middleware ----------
const auth = wrap(async (req, res, next) => {
    const h = req.headers.authorization || "";
    if (!h.startsWith("Bearer ")) return res.status(401).json({ error: "Please sign in." });
    try {
        const payload = jwt.verify(h.slice(7), SECRET);
        const user = await User.findById(payload.id);
        if (!user) throw new Error("no user");
        req.user = user;
        next();
    } catch {
        res.status(401).json({ error: "Session expired. Please sign in again." });
    }
});

// ---------- Authorization middleware ----------
const allow = (...roles) => (req, res, next) =>
    roles.includes(req.user.role) ? next() : res.status(403).json({ error: "Forbidden: you do not have access." });

// ---------- Register (always creates a student) ----------
app.post("/api/register", wrap(async (req, res) => {
    const name = str(req.body.name).trim();
    const email = str(req.body.email).trim().toLowerCase();
    const password = str(req.body.password);
    const confirm = str(req.body.confirm);
    const dept = str(req.body.dept).trim();
    const sem = str(req.body.sem) || "Semester 1";
    const degree = str(req.body.degree);

    const errors = {};
    if (!/^[A-Za-z][A-Za-z .'-]{2,59}$/.test(name)) errors.name = "Enter your full name (letters only, at least 3 characters).";
    if (!EMAIL.test(email)) errors.email = "Enter a valid university email.";
    if (password.length < 8 || !/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/\d/.test(password) || !/[^A-Za-z0-9]/.test(password))
        errors.password = "Use 8+ characters with upper, lower, number and symbol.";
    if (!confirm || confirm !== password) errors.confirm = "Passwords do not match.";
    if (!dept) errors.dept = "Select a department.";
    if (Object.keys(errors).length) return res.status(400).json({ errors });

    if (await User.findOne({ email })) return res.status(409).json({ errors: { email: "This email is already registered. Sign in instead." } });

    const count = await User.countDocuments({ role: "student" });
    await User.create({
        name, email, dept, sem, degree,
        password: await bcrypt.hash(password, 10),
        role: "student",
        studentId: "STU2026" + String(count + 1).padStart(4, "0")
    });
    res.status(201).json({ message: "Registration complete. Please sign in." });
}));

// ---------- Login ----------
app.post("/api/login", wrap(async (req, res) => {
    const email = str(req.body.email).trim().toLowerCase();
    const password = str(req.body.password);
    if (!EMAIL.test(email) || !password) return res.status(400).json({ error: "Enter a valid email and password." });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "No account found for this email. Please register first." });

    if (user.lockUntil && user.lockUntil > Date.now()) {
        const s = Math.ceil((user.lockUntil - Date.now()) / 1000);
        return res.status(429).json({ error: "Too many failed attempts. Try again in " + s + " seconds." });
    }
    if (!(await bcrypt.compare(password, user.password))) {
        user.failedAttempts += 1;
        let msg = "Incorrect password. " + (5 - user.failedAttempts) + " attempt(s) left.";
        if (user.failedAttempts >= 5) {
            user.failedAttempts = 0;
            user.lockUntil = new Date(Date.now() + 30000);
            msg = "Too many failed attempts. Locked for 30 seconds.";
        }
        await user.save();
        return res.status(401).json({ error: msg });
    }
    user.failedAttempts = 0;
    user.lockUntil = undefined;
    await user.save();
    const token = jwt.sign({ id: user._id, role: user.role }, SECRET, { expiresIn: "30m" });
    res.json({ token, user: publicUser(user) });
}));

app.get("/api/me", auth, (req, res) => res.json({ user: publicUser(req.user) }));

// ---------- Student: own marks only (uses id from the token, never from the URL) ----------
app.get("/api/marks/me", auth, allow("student"), wrap(async (req, res) => {
    const doc = await Marks.findOne({ student: req.user._id }).lean();
    res.json({ subjects: SUBJECTS, marks: doc ? doc.marks : {} });
}));

// ---------- Faculty/Admin: all students with marks ----------
app.get("/api/students", auth, allow("faculty", "admin"), wrap(async (req, res) => {
    const students = await User.find({ role: "student" }).sort({ createdAt: 1 }).lean();
    const marks = await Marks.find({ student: { $in: students.map((s) => s._id) } }).lean();
    const byId = Object.fromEntries(marks.map((m) => [String(m.student), m.marks]));
    res.json({
        subjects: SUBJECTS,
        students: students.map((s) => ({ id: s._id, name: s.name, studentId: s.studentId, dept: s.dept, sem: s.sem, marks: byId[String(s._id)] || {} }))
    });
}));

// ---------- Faculty only: save marks ----------
app.put("/api/marks/:id", auth, allow("faculty"), wrap(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ error: "Invalid student." });
    const student = await User.findOne({ _id: req.params.id, role: "student" });
    if (!student) return res.status(404).json({ error: "Student not found." });

    const clean = {};
    for (const s of SUBJECTS) {
        const n = Number(req.body.marks && req.body.marks[s]);
        if (!Number.isInteger(n) || n < 0 || n > 100) return res.status(400).json({ error: "Marks must be whole numbers from 0 to 100 (" + s + ")." });
        clean[s] = n;
    }
    await Marks.findOneAndUpdate({ student: student._id }, { $set: { marks: clean } }, { upsert: true });
    res.json({ message: "Marks saved." });
}));

// ---------- Admin: stats ----------
app.get("/api/stats", auth, allow("admin"), wrap(async (req, res) => {
    const [students, faculty, depts] = await Promise.all([
        User.countDocuments({ role: "student" }),
        User.countDocuments({ role: "faculty" }),
        User.distinct("dept", { dept: { $ne: null } })
    ]);
    res.json({ students, faculty, courses: SUBJECTS.length, departments: depts.length });
}));

// ---------- Error handler ----------
app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ error: "Server error. Please try again." });
});

mongoose.connect(MONGO_URI).then(() => {
    console.log("MongoDB connected");
    app.listen(PORT, () => console.log("Portal running at http://localhost:" + PORT));
}).catch((err) => {
    console.error("MongoDB connection failed:", err.message);
    console.error("Start MongoDB first (mongod) or set MONGO_URI.");
    process.exit(1);
});
