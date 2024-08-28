import playwright from "playwright-core";
import path from "node:path";
import { existsSync } from "node:fs";
import config from "../../../utils/config.js";

const formats = [
    "JPG",
    "PNG",
    "WEBP",
];

export class Exporter {
    constructor(filepath) {
        this.filepath = filepath;
        this.filename = path.basename(filepath);
        this.extname = path.extname(this.filename);
        this.basename = path.basename(this.filename, this.extname);
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
        if ((options.dpi != undefined) && (typeof options.dpi !== "number")) {
            throw new Error(`invalid dpi ${options.dpi}`);
        }
        if (typeof options.quality !== "number") {
            throw new Error(`invalid quality ${options.quality}`);
        }
        if (typeof options.metadata !== "boolean") {
            throw new Error(`invalid metadata ${options.metadata}`);
        }

        const browser = await playwright.chromium.launch({
            headless: true,
            timeout: 0,
        });
        const page = await browser.newPage();
        await page.goto("https://www.photopea.com");

        const upload = await page.locator("input[type=file]");
        upload.setInputFiles(this.filepath);

        await page.waitForSelector("button", { hasText: /^File$/,  });
        const file = await page.locator("button", { hasText: /^File$/ });
        await file.click();

        await page.waitForSelector("div.enab > span:has-text('Export as')");
        const exportAs = await page.locator("div.enab > span", { hasText: /^Export as$/ });
        await exportAs.click();

        await page.waitForSelector(`div.enab > span:has-text('${options.format}')`);
        const fileType = await page.locator("div.enab > span", { hasText: new RegExp(`^${options.format}$`) });
        await fileType.click();

        const settings = {};
        await page.waitForSelector("div.form.cell");
        await page.waitForSelector("button:has-text('Save')");
        settings.name = await page.locator("div.form.cell * label:has-text('Name') + input");
        settings.width = await page.locator("div.form.cell * label:has-text('Width') + input");
        settings.height = await page.locator("div.form.cell * label:has-text('Height') + input");
        if (options.dpi !== undefined) {
            settings.dpi = await page.locator("div.form.cell * label:has-text('DPI') + input");
        }
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

        if (options.dpi !== undefined) {
            await settings.dpi.clear();
            await settings.dpi.fill(`${options.dpi}`);
        }

        await settings.quality.clear();
        await settings.quality.fill(`${options.quality}`);

        await settings.save.focus();

        const waitForDownload = page.waitForEvent('download');
        await settings.save.click();
        const download = await waitForDownload;
        let downloadPath = options.overridePath ?  options.overridePath : `test.${options.format.toLowerCase()}`;
        if (!path.isAbsolute(downloadPath)) {
            downloadPath = path.join(config.cwd, downloadPath);
        }
        await download.saveAs(downloadPath);

        await browser.close();
        console.log(`done with ${this.filename}`);
    }
}

export async function importPSD(filepath) {
    if (typeof filepath !== "string") {
        throw new Error(`invalid filepath ${filepath}`);
    }
    if (!path.isAbsolute(filepath)) {
        filepath = path.join(config.cwd, filepath);
    }
    if (!existsSync(filepath)) {
        throw new Error(`file ${filepath} does not exist`);
    }

    return new Exporter(filepath);
}