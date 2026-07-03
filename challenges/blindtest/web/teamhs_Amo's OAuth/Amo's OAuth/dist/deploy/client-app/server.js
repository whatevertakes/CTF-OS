import express from "express";
import bodyParser from "body-parser";
import session from "express-session";
import axios from "axios";
import ip from "ip";
import path from "path";
import ejs from "ejs";

const app = express();
const PORT = process.env.PORT || 3000;

const RESOURCE_SERVER_URL = process.env.RESOURCE_SERVER_URL || "http://lokalhost:5000";

const CLIENT_ID = process.env.CLIENT_ID || "clientapp";
const CLIENT_SECRET = process.env.CLIENT_SECRET || "clientsecret";
const AUTH_SERVER_URL = process.env.AUTH_SERVER_URL || "http://auth-server:4000";

let AUTH_SERVER_URL_CURRENT = "";
let CLIENT_APP_URL_CURRENT = "";

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(
  session({
    secret: Math.random().toString(36).slice(2),
    resave: false,
    saveUninitialized: true,
  })
);

app.set("view engine", "ejs");
app.set("views", path.join(process.cwd(), "views"));
app.engine("ejs", ejs.__express);

function getAuthServerUrl() {
  return AUTH_SERVER_URL_CURRENT;
}

function getClientBaseUrl() {
  return CLIENT_APP_URL_CURRENT;
}

function buildAuthorizeUrl(authServerUrl, clientAppUrl, state, clientIp) {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: clientAppUrl + "/callback",
    scope: "read profile",
    state: ip.isPrivate(clientIp) ? state + "_local" : "_prod",
  });
  return `${authServerUrl}/authorize?${params.toString()}`;
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

app.get("/", (req, res) => {
  res.render("index", { authServerUrl: AUTH_SERVER_URL_CURRENT, clientAppUrl: CLIENT_APP_URL_CURRENT, session: req.session });
});

app.post("/set-auth-server", (req, res) => {
  const { authServerUrl } = req.body;
  if (authServerUrl && typeof authServerUrl === "string") {
    const trimmed = authServerUrl.trim().replace(/\/+$/, "");
    AUTH_SERVER_URL_CURRENT = trimmed;
  }
  req.session.apiResponse = null;
  res.redirect("/");
});

app.post("/set-client-url", (req, res) => {
  const { clientAppUrl } = req.body;
  if (typeof clientAppUrl === "string" && clientAppUrl.trim()) {
    CLIENT_APP_URL_CURRENT = clientAppUrl.trim().replace(/\/+$/, "");
  }
  req.session.apiResponse = null;
  res.redirect("/");
});

app.get("/login", (req, res) => {
  const authServerUrl = getAuthServerUrl();
  const clientAppUrl = getClientBaseUrl();
  if (!authServerUrl || !clientAppUrl) return res.redirect("/");

  const state = Math.random().toString(36).slice(2);
  if (ip.isPrivate(req.ip)) {
    req.session.state = state + "_local";
  }
  else {
    req.session.state = state + "_prod";
  }
  res.redirect(buildAuthorizeUrl(authServerUrl, clientAppUrl, state, req.ip));
});

app.get("/callback", async (req, res) => {
  const authServerUrl = getAuthServerUrl();
  const clientAppUrl = getClientBaseUrl();
  if (!authServerUrl) return res.redirect("/");

  const { code, error } = req.query;
  if (error) return res.status(400).send(`Authorization error: ${escapeHtml(error)}`);
  if (!code) return res.status(400).send("Missing authorization code");

  if (req.query.state !== req.session.state) {
    return res.status(400).send("Invalid state");
  }

  try {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: clientAppUrl + "/callback",
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    });
    
    const tokenResp = await axios.post(`${AUTH_SERVER_URL}/token`, body, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });

    if (tokenResp && tokenResp.data){
      req.session.tokens = tokenResp.data;
    }
    else {
      req.session.tokens = null;
    }
    req.session.apiResponse = null;
    res.redirect("/");
  } catch (e) {
    console.log(e);
    res
      .status(500)
      .send(
        "Token exchange failed: " +
          (e.response?.data ? JSON.stringify(e.response.data) : e.message)
      );
  }
});

app.get("/call-api", async (req, res) => {
  const tokens = req.session.tokens;
  if (!tokens) return res.redirect("/");

  try {
    const apiResp = await axios.get(`${RESOURCE_SERVER_URL}/api/data`, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    req.session.apiResponse = apiResp.data;
  } catch (e) {
    req.session.apiResponse = { error: e.response?.data || e.message };
  }
  res.redirect("/");
});

app.get("/refresh", async (req, res) => {
  const authServerUrl = getAuthServerUrl();
  if (!authServerUrl) return res.redirect("/");

  const tokens = req.session.tokens;
  if (!tokens?.refresh_token) return res.redirect("/");

  try {
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: tokens.refresh_token,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    });
    const tokenResp = await axios.post(`${AUTH_SERVER_URL}/token`, body, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
    req.session.tokens = tokenResp.data;
    req.session.apiResponse = null;
  } catch (e) {
    req.session.apiResponse = { error: e.response?.data || e.message };
  }
  res.redirect("/");
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

app.listen(PORT, () => {
  console.log(`Client app on http://lokalhost:${PORT}`);
});