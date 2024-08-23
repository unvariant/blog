import playwright from "playwright-core";
import path from "node:path";
import { existsSync } from "node:fs";
import { readdir } from "node:fs/promises";
import { exit } from "node:process";

class Exporter {
    constructor(filename) {
        this.filename = filename;
        this.extname = path.extname(filename);
        this.basename = path.basename(filename, this.extname);
    }

    async process(options) {
        if (formats.indexOf(options.format) == -1) {
            throw new Error(`invalid format ${options.format}`);
        }
        if (options.width && typeof options.width !== "number") {
            throw new Error(`invalid width ${options.width}`);
        }
        if (options.height && typeof options.height !== "number") {
            throw new Error(`invalid height ${options.height}`);
        }
        if (typeof options.dpi !== "number") {
            throw new Error(`invalid dpi ${options.dpi}`);
        }
        if (typeof options.quality !== "number") {
            throw new Error(`invalid quality ${options.quality}`);
        }
        if (typeof options.metadata !== "boolean") {
            throw new Error(`invalid metadata ${options.metadata}`);
        }

        const file = await page.locator("button", { hasText: /^File$/ });
        await file.click();
        const exportAs = await page.locator("div.enab > span", { hasText: /^Export as$/ });
        console.log("exporting file");
        await exportAs.click();
        const fileType = await page.locator("div.enab > span", { hasText: new RegExp(`^${options.format}$`) });
        await fileType.click();

        const settings = {};
        settings.name = await page.locator("div.form.cell * label:has-text('Name') + input");
        settings.width = await page.locator("div.form.cell * label:has-text('Width') + input");
        settings.height = await page.locator("div.form.cell * label:has-text('Height') + input");
        settings.dpi = await page.locator("div.form.cell * label:has-text('DPI') + input");
        settings.quality = await page.locator("div.form.cell * label:has-text('Quality:') + input");
        settings.aspectRatio = await page.locator("div.form.cell * [title='Keep Aspect Ratio']");
        settings.save = await page.locator("button:has-text('Save')");

        await settings.aspectRatio.click();

        await settings.name.clear();
        await settings.name.fill(this.basename);

        await settings.width.clear();
        await settings.width.fill(`${options.width}`);

        await settings.height.clear();
        await settings.height.fill(`${options.height}`);

        await settings.dpi.clear();
        await settings.dpi.fill(`${options.dpi}`);

        await settings.quality.clear();
        await settings.quality.fill(`${options.quality}`);

        await settings.save.focus();

        const waitForDownload = page.waitForEvent('download');
        await settings.save.click();
        const download = await waitForDownload;
        let downloadPath = options.overridePath ?  options.overridePath : `test.${options.format.toLowerCase()}`;
        if (!path.isAbsolute(downloadPath)) {
            downloadPath = path.join(cwd, downloadPath);
        }
        await download.saveAs(downloadPath);
    }
}

async function importPSD(filepath) {
    if (typeof filepath !== "string") {
        throw new Error(`invalid filepath ${filepath}`);
    }
    if (!path.isAbsolute(filepath)) {
        filepath = path.join(cwd, filepath);
    }
    if (!existsSync(filepath)) {
        throw new Error(`file ${filepath} does not exist`);
    }
    const upload = await page.locator("input[type=file]");
    upload.setInputFiles(filepath);
    return new Exporter(path.basename(filepath));
}

const cwd = path.resolve(".");
const formats = [
    "JPG",
    "PNG",
    "WEBP",
];
const target = "src/blog/random/gallery"
const psds = (await readdir(path.join(cwd, target))).filter(file => file.endsWith(".psd"));
if (psds.length == 0) {
    console.log(`nothing to do. exiting.`);
    exit(0);
}

const browser = await playwright.chromium.launch({
    headless: true,
});
const page = await browser.newPage();
await page.goto("https://www.photopea.com");

for (const psd of psds) {
    const file = await importPSD(path.join(target, psd));
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