const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const User = require("./models/User");
const cookieParser = require('cookie-parser');  // Your user schema
const app = express();

// Load environment variables
dotenv.config();

// Middleware
app.use(cors({
    origin: 'http://localhost:3000', // Your frontend URL
    credentials: true, // Allow cookies to be sent
  }));
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser()); 

// MongoDB Connection
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.log("MongoDB connection error", err));

// JWT Middleware for verifying token
function verifyToken(req, res, next) {
    const token = req.header('auth-token');
    console.log("token", token)
  
    if (!token) return res.status(401).json("Access denied");
  
    try {
      const verified = jwt.verify(token, process.env.JWT_SECRET);
      console.log("verified", verified)
      req.user = verified;
      next();
    } catch (err) {
      res.status(400).json("Invalid token");
    }
  }
  

// Register Route
app.post("/register", async (req, res) => {
  const { name, role, empId, email, password } = req.body;

  if (!name || !empId || !password || !role || (role === "admin" && !email)) {
    return res
      .status(400)
      .json({ message: "All fields are required for registration" });
  }

  try {
    const existingUser = await User.findOne({ empId });
    if (existingUser) {
      return res
        .status(400)
        .json({ message: "User with this Employee ID already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      name,
      empId,
      email,
      password: hashedPassword,
      role,
    });

    await newUser.save();
    res.status(201).json({ message: "Account created successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json("Server error");
  }
});

// Login Route
app.post("/login", async (req, res) => {
  const { empId, password, email } = req.body;

  try {
    const user = await User.findOne({ empId });
    if (!user) return res.status(400).json({ message: "User not found" });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword)
      return res.status(400).json({ message: "Invalid credentials" });

    // Admin requires email for login validation
    if (user.role === "admin" && user.email !== email) {
      return res
        .status(400)
        .json({ message: "Admin requires valid email for login" });
    }

    // Generate JWT Token
    const token = jwt.sign(
      { id: user._id, role: user.role, empId: user.empId },
      process.env.JWT_SECRET,
      { expiresIn: "1m" }
    );

     // Store token in cookies if desired
 // Store token in cookies if desired
 res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict' });
    res
      .status(200)
      .json({
        message: "Login successful",
        token,
        empId: user.empId,
        email: user.email,
      });
  } catch (error) {
    console.error(error);
    res.status(500).json("Server error");
  }
});

// logout
// Logout route
app.delete('/logout', verifyToken, (req, res) => {
    try {
      res.clearCookie('token', { httpOnly: true, secure: true, sameSite: 'strict' });
      res.status(200).json({ message: 'Successfully logged out' });
    } catch (error) {
      res.status(500).json({ message: 'Logout failed', error });
    }
  });
  

// Admin-only route (fetch all medical rep details)
app.get("/admin/medical-reps", verifyToken, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json("Access denied. Admins only.");
  }

  try {
    const medicalReps = await User.find(
      { role: "medical_rep" },
      { password: 0 }
    ); // Exclude password
    res.status(200).json(medicalReps);
  } catch (error) {
    console.error(error);
    res.status(500).json("Server error");
  }
});

// Medical Rep-only route (own dashboard)
// Logout Route
app.delete('/logout', verifyToken, (req, res) => {
    try {
      // Clear the JWT token from the cookies
      res.clearCookie('token', { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict' });
      
      return res.status(200).json({ message: 'Successfully logged out' });
    } catch (error) {
      return res.status(500).json({ message: 'Logout failed', error });
    }
  });
  

// Catch all 404 errors
app.use((req, res, next) => {
  res.status(404).json({ message: "Route not found" });
});

// Start the server
const PORT = process.env.PORT || 3002;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
