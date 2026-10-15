// Creates demo admin, faculty and student accounts (safe to run more than once)
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const { User, Marks } = require("./models");

const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/university_portal";

(async () => {
    await mongoose.connect(MONGO_URI);
    const demo = [
        { name: "System Admin", email: "admin@demo.edu", role: "admin", pw: "Admin@123" },
        { name: "Dr. Priya Nair", email: "faculty@demo.edu", role: "faculty", pw: "Faculty@123", dept: "Computer Science" },
        { name: "Liam Chen", email: "student@demo.edu", role: "student", pw: "Student@123", studentId: "STU20260001",
          dept: "Electronics & Communication", sem: "Semester 2", degree: "Bachelor of Technology (B.Tech)" }
    ];
    for (const d of demo) {
        const { pw, ...rest } = d;
        let u = await User.findOne({ email: d.email });
        if (!u) u = await User.create({ ...rest, password: await bcrypt.hash(pw, 10) });
        if (d.role === "student") {
            await Marks.findOneAndUpdate({ student: u._id },
                { $set: { marks: { "Data Structures": 78, "Database Management System": 85, "Computer Networks": 69, "Web Technologies": 91 } } },
                { upsert: true });
        }
    }
    console.log("Demo users ready: admin@demo.edu, faculty@demo.edu, student@demo.edu");
    await mongoose.disconnect();
})().catch((e) => { console.error(e.message); process.exit(1); });
