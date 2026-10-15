const mongoose = require("mongoose");

const SUBJECTS = ["Data Structures", "Database Management System", "Computer Networks", "Web Technologies"];

const userSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },            // bcrypt hash, never plain text
    role: { type: String, enum: ["admin", "faculty", "student"], default: "student" },
    studentId: String,
    dept: String,
    sem: String,
    degree: String,
    failedAttempts: { type: Number, default: 0 },
    lockUntil: Date
}, { timestamps: true });

const marksSchema = new mongoose.Schema({
    student: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, unique: true },
    marks: { type: mongoose.Schema.Types.Mixed, default: {} }   // { "Data Structures": 78, ... }
}, { timestamps: true });

module.exports = {
    SUBJECTS,
    User: mongoose.model("User", userSchema),
    Marks: mongoose.model("Marks", marksSchema)
};
