import express from "express";
import bodyParser from "body-parser";
import jwt from "jsonwebtoken";
import { nanoid } from "nanoid";
import path from "path";
import ejs from "ejs";
import cookieParser from "cookie-parser";
import { URL } from "url";

const app = express();
const PORT = process.env.PORT || 4000;
const TOKEN_SECRET = process.env.TOKEN_SECRET || "dev_secret_123";
const CLIENT_ID = process.env.CLIENT_ID || "clientapp";
const CLIENT_SECRET = process.env.CLIENT_SECRET || "clientsecret";
const REDIRECT_HOST = process.env.REDIRECT_HOST || ".host.dreamhack.games";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin1234";

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.set("view engine", "ejs");
app.set("views", path.join(process.cwd(), "views"));
app.engine("ejs", ejs.__express);

const users = [{ id: "test", username: "amo", password: "amo1234", name: "Amo" }, { id: "admin", username: "administrator", password: ADMIN_PASSWORD, name: "aaaddd" }];
const clients = [{ id: CLIENT_ID, secret: CLIENT_SECRET, name: "First Client App" }];
const authCodes = new Map();
const refreshTokens = new Map();

function findUser(username, password) {
  return users.find(u => u.username === username && u.password === password);
}
function validateClient(clientId, redirectUri) {
  const c = clients.find(c => c.id === clientId);
  if (!c) return null;
  const host = new URL(redirectUri).hostname;
  if (host.endsWith(REDIRECT_HOST) === false && host.endsWith("client-app") === false) return null;
  return c;
}

app.get("/", (_req, res) => res.send("Auth Server OK"));

app.get("/authorize", (req, res) => {
  const { response_type, client_id, redirect_uri, scope = "", state = "" } = req.query;

  if (response_type !== "code") {
    return res.status(400).send("unsupported response_type");
  }
  const client = validateClient(client_id, redirect_uri);
  if (!client) {
    return res.status(400).send("invalid client or redirect_uri");
  }

  return res.render("login", { params: { response_type, client_id, redirect_uri, scope, state } });
});

app.post("/authorize", (req, res) => {
  const { response_type, client_id, redirect_uri, scope = "", state = "", username, password } = req.body;
  if (response_type !== "code") return res.status(400).send("unsupported response_type");

  const client = validateClient(client_id, redirect_uri);
  if (!client) return res.status(400).send("invalid client or redirect_uri");

  const user = findUser(username, password);
  if (!user) {
    return res.status(302).redirect(`${redirect_uri}?error=access_denied&state=${encodeURIComponent(state)}`);
  }

  const code = nanoid(24);
  const expiresAt = Date.now() + 5 * 60 * 1000; // 5 min
  authCodes.set(code, { clientId: client.id, redirectUri: redirect_uri, userId: user.id, scope, expiresAt });

  const location = `${redirect_uri}?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`;
  return res.redirect(location);
});

app.post("/token", (req, res) => {
  const { grant_type } = req.body;

  if (grant_type === "authorization_code") {
    const { code, redirect_uri, client_id, client_secret } = req.body;

    if (!code || !redirect_uri || !client_id) {
      return res.status(400).json({ error: "invalid_request", error_description: "missing parameters" });
    }
    const client = clients.find(c => c.id === client_id);
    if (!client || client.secret !== client_secret) {
      return res.status(401).json({ error: "invalid_client" });
    }

    const entry = authCodes.get(code);
    if (!entry) return res.status(400).json({ error: "invalid_grant" });
    if (entry.clientId !== client_id) {
      return res.status(400).json({ error: "invalid_grant", error_description: "mismatched redirect_uri/client_id" });
    }
    if (Date.now() > entry.expiresAt) {
      authCodes.delete(code);
      return res.status(400).json({ error: "invalid_grant", error_description: "code expired" });
    }

    authCodes.delete(code);

    const accessToken = jwt.sign(
      { sub: entry.userId, scope: entry.scope || "", aud: "resource-api" },
      TOKEN_SECRET,
      { algorithm: "HS256", expiresIn: "1h", issuer: "demo-auth-server" }
    );

    // Issue refresh token
    const refreshToken = nanoid(32);
    refreshTokens.set(refreshToken, { userId: entry.userId, scope: entry.scope, clientId: client_id });

    return res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 3600,
      refresh_token: refreshToken,
      scope: entry.scope
    });
  }

  if (grant_type === "refresh_token") {
    const { refresh_token, client_id, client_secret } = req.body;
    const client = clients.find(c => c.id === client_id);
    if (!client || client.secret !== client_secret) {
      return res.status(401).json({ error: "invalid_client" });
    }
    const entry = refreshTokens.get(refresh_token);
    if (!entry || entry.clientId !== client_id) {
      return res.status(400).json({ error: "invalid_grant" });
    }

    const accessToken = jwt.sign(
      { sub: entry.userId, scope: entry.scope || "", aud: "resource-api" },
      TOKEN_SECRET,
      { algorithm: "HS256", expiresIn: "0.5h", issuer: "auth-server" }
    );
    
    return res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 1800,
      refresh_token: refresh_token,
      scope: entry.scope
    });
  }

  return res.status(400).json({ error: "unsupported_grant_type" });
});

app.listen(PORT, () => {
  console.log(`Auth server running on http://lokalhost:${PORT}`);
});
