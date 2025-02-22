require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("./models/User"); // Import User model

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = "your_secret_key"; // Use a secure secret key

// 🔹 Connect to MongoDB
mongoose
  .connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch((err) => console.error("❌ MongoDB Connection Error:", err));

// 🔹 User Registration Route (Without Username)
app.post("/api/signup", async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body;

    // Check if email already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ success: false, message: "Email already exists" });

    // Hash Password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create User (without username)
    const newUser = new User({ firstName, lastName, email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ success: true, message: "User registered successfully", userId: newUser._id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});

// 🔹 User Login Route
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    // Check if user exists by username
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ success: false, message: "User not found" });

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ success: false, message: "Invalid credentials" });

    // Generate JWT token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "1h" });

    res.json({ success: true, token, userId: user._id, username: user.username });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});


// 🔹 Set Username Route (After Login)
app.post("/api/update-details", async (req, res) => {
  try {
    const { userId, username, category } = req.body;

    if (!userId || !username || !category) {
      return res.status(400).json({ success: false, message: "All fields are required" });
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { username, category },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    res.json({ success: true, message: "Details updated successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});

app.get("/api/user-details", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1]; // Get token from headers
    if (!token) return res.status(401).json({ success: false, message: "Unauthorized" });

    const decoded = jwt.verify(token, JWT_SECRET); // Decode JWT
    const user = await User.findById(decoded.userId).select("firstName lastName email");

    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    res.json({ success: true, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});



// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
