import playwright from "playwright-core";
import path from "node:path";
import { readdir } from "node:fs/promises";
import { exit } from "node:process";
import config from "./src/utils/config.js";
import { importPSD } from "./src/blog/random/gallery/Optimize.js";

const target = "."
const psds = (await readdir(path.join(config.cwd, target))).filter(file => file.endsWith(".psd"));
if (psds.length == 0) {
    console.log(`nothing to do. exiting.`);
    exit(0);
}

const browser = await playwright.chromium.launch({
    headless: true,
    timeout: 0,
});
const page = await browser.newPage();
await page.goto("https://www.photopea.com");

for (const psd of psds) {
    const file = await importPSD(page, path.join(target, psd));
    const overridePath = path.join(target, `${file.basename}.jpg`);
    await file.process({
        format: "JPG",
        width: 1500,
        height: 1500,
        dpi: 300,
        quality: 100,
        metadata: false,
        overridePath,
    })
}

await browser.close();