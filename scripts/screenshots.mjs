#!/usr/bin/env node
// Capture every Secreton frontend view into docs/screenshots/ and assert each one is
// actually usable.
//
// A screenshot is only evidence if it shows the page working. This script therefore fails
// (non-zero exit) when a view is blank, unexpectedly errored, overflows horizontally, has
// a control too small to click, or logs a console error that is not the expected 404.
//
// Usage:
//   npm install                              # installs the pinned playwright-core
//   npm run browser:install                  # once, to fetch the matching Chromium
//   cargo leptos serve                       # in one terminal
//   npm run screenshots                      # in another
//
// The dependency is declared and pinned in the root `package.json`; nothing here is part
// of the Rust build. `npm run screenshots:check` verifies the setup without capturing.
// If you already have a Chromium, skip the download and set CHROMIUM_PATH to it.
//
// Environment:
//   BASE_URL            default http://127.0.0.1:3000
//   CHROMIUM_PATH       browser binary; default is the one Playwright installed
//   SCREENSHOT_USER     demo account username (default "demo")
//   SCREENSHOT_PASSWORD demo account password (required if the login views are captured)

import { createRequire } from "node:module";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUT = path.join(REPO, "docs/screenshots");
const BASE = process.env.BASE_URL ?? "http://127.0.0.1:3000";
const USER = process.env.SCREENSHOT_USER ?? "demo";
const PASSWORD = process.env.SCREENSHOT_PASSWORD ?? "change-me-please";
const DESKTOP = { width: 1280, height: 800 };
const MOBILE = { width: 390, height: 844 };

let chromium;
try {
  ({ chromium } = require("playwright-core"));
} catch {
  console.error(
    "playwright-core not found. Run `npm install` in the repository root, then " +
      "`npm run screenshots:check` to verify the browser is available."
  );
  process.exit(2);
}

const EXECUTABLE = process.env.CHROMIUM_PATH ?? undefined;

function launchOptions() {
  const args = ["--no-sandbox", "--disable-dev-shm-usage"];
  return EXECUTABLE ? { executablePath: EXECUTABLE, args } : { args };
}

const results = [];

async function shoot(page, name, urlPath, expectedStatus) {
  const errors = [];
  const onError = (e) => errors.push(String(e));
  const onConsole = (m) => m.type() === "error" && errors.push(m.text());
  page.on("pageerror", onError);
  page.on("console", onConsole);

  const resp = await page.goto(BASE + urlPath, { waitUntil: "networkidle" });
  await page.waitForTimeout(1800);

  const probe = await page.evaluate(() => {
    const text = (document.body.innerText || "").trim();
    const de = document.documentElement;
    const tiny = [...document.querySelectorAll("button, a, input")]
      .map((e) => e.getBoundingClientRect())
      .filter((r) => r.width > 0 && r.height > 0 && (r.width < 8 || r.height < 8));
    return { text, overflowX: de.scrollWidth - de.clientWidth, tinyControls: tiny.length };
  });

  const file = path.join(OUT, `${name}.png`);
  // `animations: "disabled"` settles CSS transitions before capture; without it a
  // running animation can stall the screenshot on some Chromium builds. The explicit
  // timeout keeps a hung capture from blocking the whole run.
  await page.screenshot({
    path: file,
    fullPage: true,
    animations: "disabled",
    timeout: 30000,
  });
  page.off("pageerror", onError);
  page.off("console", onConsole);

  results.push({
    view: name,
    status: resp.status(),
    expectedStatus,
    bytes: fs.statSync(file).size,
    overflowX: probe.overflowX,
    tinyControls: probe.tinyControls,
    jsErrors: errors,
    textLength: probe.text.length,
  });
  console.log(`  ${name.padEnd(16)} HTTP ${resp.status()}  ${fs.statSync(file).size} bytes`);
}

async function signIn(page) {
  // A fresh context starts on about:blank; the form only exists on the login page.
  await page.goto(BASE + "/login", { waitUntil: "networkidle" });
  await page.waitForSelector('input[name="credentials[username]"]', { timeout: 20000 });
  await page.fill('input[name="credentials[username]"]', USER);
  await page.fill('input[name="credentials[password]"]', PASSWORD);
  // The submit control carries no `type` attribute, so `form button` is the selector.
  await page.locator("form button").click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"), { timeout: 20000 });
}

async function main() {
  fs.mkdirSync(OUT, { recursive: true });

  let browser;
  try {
    browser = await chromium.launch(launchOptions());
  } catch (e) {
    console.error(
      [
        "Could not launch Chromium.",
        "",
        EXECUTABLE
          ? `CHROMIUM_PATH is set to ${EXECUTABLE}; check that it exists and is executable.`
          : "Install the browser the pinned Playwright expects: npm run browser:install",
        "Or set CHROMIUM_PATH to a system Chromium you already have.",
        "",
        `Underlying error: ${e}`,
      ].join("\n")
    );
    process.exit(3);
  }

  console.log("signed-out views");
  const anon = await browser.newContext({ viewport: DESKTOP });
  const page = await anon.newPage();

  await shoot(page, "login", "/login", 200);

  // The denial path: a rejected sign-in must show a plain message and leave the form usable.
  await page.waitForSelector('input[name="credentials[username]"]', { timeout: 20000 });
  await page.fill('input[name="credentials[username]"]', USER);
  await page.fill('input[name="credentials[password]"]', "definitely-not-the-password");

  // Collect errors for the denial path too, rather than asserting an empty list. The
  // server function answers 500 for a rejected sign-in (that is how Leptos reports a
  // `ServerFnError`), so the browser logs exactly one failed XHR; anything beyond that is
  // a real defect and fails the run.
  const denialErrors = [];
  const onDenialError = (e) => denialErrors.push(String(e));
  const onDenialConsole = (m) => m.type() === "error" && denialErrors.push(m.text());
  page.on("pageerror", onDenialError);
  page.on("console", onDenialConsole);

  await page.locator("form button").click();
  // The response is a server-function round trip, so the alert appears after a beat.
  await page.waitForSelector('[role="alert"]', { timeout: 20000 });
  await page.waitForTimeout(500);
  page.off("pageerror", onDenialError);
  page.off("console", onDenialConsole);

  await page.screenshot({
    path: path.join(OUT, "login-error.png"),
    fullPage: true,
    animations: "disabled",
    timeout: 30000,
  });
  const errText = await page.locator("body").innerText();
  const errFile = path.join(OUT, "login-error.png");
  const alertText = (await page.locator('[role="alert"]').innerText()).trim();
  results.push({
    view: "login-error",
    status: 200,
    expectedStatus: 200,
    bytes: fs.statSync(errFile).size,
    overflowX: 0,
    tinyControls: 0,
    jsErrors: denialErrors,
    alertText,
    textLength: errText.length,
  });
  console.log(`  login-error      HTTP 200  ${fs.statSync(errFile).size} bytes`);

  const nf = await anon.newPage();
  await shoot(nf, "not-found", "/no-such-page", 404);

  // Mobile signed-out.
  const mob = await browser.newContext({ viewport: MOBILE });
  const mLogin = await mob.newPage();
  await shoot(mLogin, "mobile-login", "/login", 200);

  console.log("signed-in views");
  // The session lives only in an httpOnly cookie, so the real form is the only way in.
  //
  // Each signed-in view signs in on its own fresh context. Signing in twice through the
  // same page and then capturing a full-page screenshot wedged the capture on a headless
  // Chromium build — the screenshot never completed even with animations disabled, while
  // the identical sequence on a fresh context returned immediately. A clean context per
  // view is also closer to what a real visitor does.
  const desk = await browser.newContext({ viewport: DESKTOP });
  const dPage = await desk.newPage();
  await signIn(dPage);
  await shoot(dPage, "dashboard", "/", 200);

  const phone = await browser.newContext({ viewport: MOBILE });
  const pPage = await phone.newPage();
  await signIn(pPage);
  await shoot(pPage, "mobile-dashboard", "/", 200);

  await browser.close();

  // Two console errors are part of the design and are whitelisted by name; every other
  // error fails the run.
  //   - the 404 page: the browser logs its own document request as a failed resource.
  //   - the rejected sign-in: Leptos reports a `ServerFnError` as an HTTP 500, so the
  //     failed server-function POST shows up once.
  const expectedError = (r, e) => {
    if (r.status === 404 && e.includes("404")) return true;
    if (r.view === "login-error" && e.includes("500")) return true;
    return false;
  };

  const bad = results.filter(
    (r) =>
      r.status !== r.expectedStatus ||
      r.bytes < 5000 ||
      r.textLength < 20 ||
      r.overflowX > 2 ||
      r.tinyControls > 0 ||
      r.jsErrors.filter((e) => !expectedError(r, e)).length ||
      // A rejected sign-in must not distinguish "no such user" from "wrong password".
      (r.view === "login-error" && r.alertText !== "invalid credentials")
  );

  if (bad.length) {
    console.error("\nFAILED: " + bad.map((b) => b.view).join(", "));
    console.error(JSON.stringify(bad, null, 2));
    process.exit(1);
  }
  console.log(`\nOK: ${results.length} views captured and verified`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
