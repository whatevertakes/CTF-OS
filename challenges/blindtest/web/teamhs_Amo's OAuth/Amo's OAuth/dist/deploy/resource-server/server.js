import express from "express";
import bodyParser from "body-parser";
import jwt from "jsonwebtoken";
import fs from "fs";
import cors from "cors";

const app = express();
const PORT = process.env.PORT || 5000;
const TOKEN_SECRET = process.env.TOKEN_SECRET || "dev_secret_123";

app.use(bodyParser.json());
app.use(cors());

function authenticate(req, res, next) {
  const auth = req.headers.authorization || "";
  const [, token] = auth.split(" ");
  if (!token) return res.status(401).json({ error: "missing_token" });
  try {
    const payload = jwt.verify(token, TOKEN_SECRET, { algorithms: ["HS256"], audience: "resource-api" });
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: "invalid_token", details: e.message });
  }
}

app.get("/", (req, res) => res.send("Resource Server OK"));

app.get("/api/data", authenticate, (req, res) => {
  let flag = "";
  if (req.user.sub == "admin") {
    flag = fs.readFileSync("/flag", "utf-8");
  }
  res.json({
    message: "Protected data",
    user: { id: req.user.sub },
    message: req.user.sub === "admin" ? `Hello, Admin! ${flag}` : "Hello, User!",
    scope: req.user.scope
  });
});

app.listen(PORT, () => console.log(`Resource server on http://lokalhost:${PORT}`));
