import express from "express";
import bodyParser from "body-parser";
import puppeteer from "puppeteer";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
const PORT = process.env.PORT || 8000;
const PUPPETEER_EXECUTABLE_PATH = process.env.PUPPETEER_EXECUTABLE_PATH || "/usr/bin/chromium";

const USERNAME = "administrator";
const PASSWORD = process.env.ADMIN_PASSWORD || "admin1234";

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(bodyParser.urlencoded({ extended: true }));

app.get("/", (req, res) => {
  res.redirect("/report");
})

app.get("/report", (req, res) => {
  res.render("report", { result: null, defaultUrl: "http://client-app:3000/login" || "" });
});

app.post("/report", async (req, res) => {
  const { url } = req.body;
  const result = { success: false, logs: [] };

  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    return res.render("report")
  }

  const launchOptions = {
    headless: "new",
    executablePath: PUPPETEER_EXECUTABLE_PATH,
    args: ["--no-sandbox", "--disable-setuid-sandbox"]
  };

  let browser;
  try {
    browser = await puppeteer.launch(launchOptions);
    const page = await browser.newPage();

    await page.goto(url, { waitUntil: "networkidle2" });
    await page.waitForSelector('form[action="/authorize"]');

    await page.type('input[name="username"]', USERNAME, { delay: 10 });
    await page.type('input[name="password"]', PASSWORD, { delay: 10 });
    
    await Promise.all([
      page.click('button[type="submit"]'),
      page.waitForNavigation({ waitUntil: "networkidle2" })
    ]);

    result.success = true;
  } catch (err) {
    console.log(`error: ${err.message}`);
  } finally {
    if (browser) await browser.close();
  }

  res.render("report", { result, defaultUrl: url });
});

app.listen(PORT, () => {
  console.log(`Bot running at http://localhost:${PORT}/report`);
});
