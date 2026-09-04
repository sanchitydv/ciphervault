import { chromium } from "playwright-core";
import { readFile } from "node:fs/promises";

const baseUrl = process.env.BASE_URL ?? "http://localhost:3000";
const executablePath =
  process.env.CHROME_PATH ??
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const plaintext = "CipherVault browser smoke test: encrypted before upload.";

const browser = await chromium.launch({ headless: true, executablePath });
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
const browserErrors = [];
page.on("pageerror", (error) => browserErrors.push(error.message));

try {
  await page.goto(baseUrl, { waitUntil: "networkidle" });
  await page.screenshot({ path: "/tmp/ciphervault-auth.png", fullPage: true });

  const uniqueEmail = `browser-${Date.now()}@example.com`;
  const accountPassword = "browser smoke account password 2026";
  const vaultPassphrase = "browser smoke vault passphrase 2026";
  await page.getByLabel("Email address").fill(uniqueEmail);
  await page.getByLabel("Account password").fill(accountPassword);
  await page.getByRole("button", { name: "Create secure account" }).click();

  await page.getByRole("heading", { name: "Set up your private vault" }).waitFor();
  await page.getByLabel("Vault passphrase").fill(vaultPassphrase);
  await page.getByLabel("Confirm passphrase").fill(vaultPassphrase);
  await page.getByRole("button", { name: /Create encrypted vault/ }).click();

  await page.getByRole("heading", { name: "Good to see you." }).waitFor();
  await page.locator('input[type="file"]').setInputFiles({
    name: "browser-proof.txt",
    mimeType: "text/plain",
    buffer: Buffer.from(plaintext),
  });
  await page.getByText("browser-proof.txt", { exact: true }).waitFor();

  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download browser-proof.txt" }).click();
  const download = await downloadPromise;
  const downloadedPath = await download.path();
  if (!downloadedPath || (await readFile(downloadedPath, "utf8")) !== plaintext) {
    throw new Error("Downloaded plaintext did not match the uploaded file");
  }

  await page.getByRole("button", { name: "Lock vault" }).click();
  await page.getByRole("heading", { name: "Unlock your files" }).waitFor();
  await page.getByLabel("Vault passphrase").fill(vaultPassphrase);
  await page.getByRole("button", { name: "Unlock vault" }).click();
  await page.getByText("browser-proof.txt", { exact: true }).waitFor();
  await page.screenshot({ path: "/tmp/ciphervault-dashboard.png", fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: "/tmp/ciphervault-mobile.png", fullPage: true });

  if (browserErrors.length) {
    throw new Error(`Browser errors: ${browserErrors.join(" | ")}`);
  }
  console.log(JSON.stringify({ ok: true, tested: ["register", "vault setup", "encrypt/upload", "decrypt/download", "lock/unlock"] }));
} finally {
  await browser.close();
}
