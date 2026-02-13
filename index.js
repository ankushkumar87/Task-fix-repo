   require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const requestLogger = require("./middleware/logger");
const authMiddleware = require("./middleware/auth");

const app = express();

const loginSessions = {};
const otpStore = {};

app.use(requestLogger);
app.use(express.json());
app.use(cookieParser());

app.post("/auth/login", (req, res) => {
  try {
    const { email, password } = req.body;
      
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password required" });
    }

    const loginSessionId = crypto.randomBytes(32).toString("hex");
    const otp = Math.floor(100000 + Math.random() * 900000);

    loginSessions[loginSessionId] = {
      email,
      createdAt: Date.now(),
      expiresAt: Date.now() + 2 * 60 * 10000,
    };

    otpStore[loginSessionId] = otp;

    console.log(`[OTP] ${otp} for session ${loginSessionId}`);

    return res.status(200).json({
      message: "OTP sent",
      loginSessionId,
    });
   }catch (error) {
    return res.status(500).json({ message: "Login failed" });
  }
});

app.post("/auth/verify-otp", (req, res) => {
  try {
    const { loginSessionId, otp } = req.body;

    if (!loginSessionId || !otp) {
      return res.status(400).json({
        error: "loginSessionId and otp required",
      });
    }

    const session = loginSessions[loginSessionId];

    if (!session) {
      return res.status(401).json({ error: "Invalid session" });
    }

    if (Date.now() > session.expiresAt) {
      delete loginSessions[loginSessionId];
      delete otpStore[loginSessionId];
      return res.status(401).json({ error: "Session expired" });
    }

    if (parseInt(otp) !== otpStore[loginSessionId]) {
      return res.status(401).json({ error: "Invalid OTP" });
    }

  
    delete otpStore[loginSessionId];

    res.cookie("session_token", loginSessionId, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 15 * 60 * 1000,
    });

    return res.status(200).json({
      message: "OTP verified",
    });
  } catch (error) {
    return res.status(500).json({
      message: "OTP verification failed",
    });
  }
});

app.post("/auth/token", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Unauthorized - valid session required",
      });
    }

    const sessionId = authHeader.replace("Bearer ", "");
    const session = loginSessions[sessionId];

    if (!session) {
      return res.status(401).json({ error: "Invalid session" });
    }

    if (Date.now() > session.expiresAt) {
      delete loginSessions[sessionId];
      return res.status(401).json({ error: "Session expired" });
    }

    const secret = process.env.JWT_SECRET || "ankush##2123";

    const accessToken =jwt.sign(
      { email: session.email }, 
      secret, 
      { expiresIn: "15m" });

    delete loginSessions[sessionId];

    return res.status(200).json({
      access_token: accessToken,
      expires_in:100000,
    });
  } catch (error) {
    return res.status(500).json({
      message: "Token generation failed",
    });
  }
});

app.get("/protected", authMiddleware, (req, res) => {
  return res.status(200).json({
    message: "Access granted to protected resource",
    user: req.user,
   success_flag: `FLAG-${Buffer.from(req.user.email + "_COMPLETED_ASSIGNMENT").toString('base64')}`
  });
});

const PORT=3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
