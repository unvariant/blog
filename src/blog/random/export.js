import puppeteer from 'puppeteer';
import fs from "node:fs/promises";
import path from "node:path";
import { existsSync } from 'node:fs';

// Launch the browser and open a new blank page
const browser = await puppeteer.launch({
    headless: false,
    timeout: 0,
});

const page = await browser.newPage();

const client = await page.createCDPSession();
await client.send('Page.setDownloadBehavior', {
    behavior: 'allow',
    downloadPath: '/tmp/' // Use an absolute path
});

const formats = [
    "PNG",
    "JPG",
    "WEBP",
];

async function process(options) {
    const format = options.format;
    const width = options.width;
    const height = options.height;
    const dpi = options.dpi;
    const quality = options.quality;
    const metadata = options.metadata;
    const filepath = options.filepath;

    if (typeof filepath !== "string") {
        throw new Error(`invalid path ${filepath}`);
    }
    if (formats.indexOf(format) == -1) {
        throw new Error(`invalid format ${format}`);
    }
    if (typeof width !== "number") {
        throw new Error(`invalid width ${width}`);
    }
    if (typeof height !== "number") {
        throw new Error(`invalid height ${height}`);
    }
    if (typeof dpi !== "number") {
        throw new Error(`invalid dpi ${dpi}`);
    }
    if (typeof quality !== "number") {
        throw new Error(`invalid quality ${quality}`);
    }
    if (typeof metadata !== "boolean") {
        throw new Error(`invalid metadata ${metadata}`);
    }

    // Navigate the page to a URL.
    await page.goto('https://www.photopea.com');

    const upload = await page.$("input[type=file]");
    await upload.uploadFile(filepath);

    const file = await page.locator("button ::-p-text(File)");
    await file.click();
    const exportAs = await page.locator("div.enab > span ::-p-text(Export as)");
    console.log("opening file");
    await exportAs.click();
    const fileType = await page.locator(`div.enab > span ::-p-text(${format})`);
    await fileType.click();

    async function clickCheckBox(label) {
        await page.$eval(`div.form.cell * label ::-p-text(${label})`, e => e.previousSibling.click());
    }

    async function setInput(field, value) {
        await field.wait();
        const handle = await field.waitHandle();
        await handle.focus();
        do {
            await page.evaluate((elem) => elem.value = "Z", handle);
        } while ("Z" !== (await page.evaluate((elem) => elem.value, handle)));
        await page.keyboard.press('Backspace');
        await page.keyboard.type(`${value}`);
    }

    const settings = {};
    settings.name = await page.locator("div.form.cell * label ::-p-text(Name) + input");
    settings.width = await page.locator("div.form.cell * label ::-p-text(Width) + input");
    settings.height = await page.locator("div.form.cell * label ::-p-text(Height) + input");
    settings.dpi = await page.locator("div.form.cell * label ::-p-text(DPI) + input");
    settings.quality = await page.locator("div.form.cell * label ::-p-text(Quality:) + input");
    settings.aspectRatio = await page.locator("div.form.cell * [title='Keep Aspect Ratio']");
    settings.save = await page.locator("button ::-p-text(Save)");
    await settings.save.wait();

    await settings.aspectRatio.click();
    await setInput(settings.name, filepath);
    await setInput(settings.dpi, dpi);
    await setInput(settings.quality, quality);
    if (metadata) {
        await clickCheckBox("attach metadata");
    }
    await setInput(settings.width, width);
    await setInput(settings.height, height);

    await page.evaluate(function() {
        class A extends Blob {
            constructor(a, b) {
                super(a, b);
                if (this.size > 100) {
                    window.lastCapturedBlob = this.size;
                }
            }
        }
        window.Blob = A;
    });
    await settings.save.click();

    while (true) {
        const download = await page.evaluate(() => window.lastCapturedBlob);
        console.log(download);
        if (download && 0) {
            break;
        }
        await new Promise(resolve => setTimeout(resolve, 500));
    }
    
    console.log('done!');
}

await process({
    filepath: "./neostar.psd",
    format: "JPG",
    width: 500,
    height: 500,
    dpi: 350,
    quality: 50,
    metadata: true,
});
// await browser.close();