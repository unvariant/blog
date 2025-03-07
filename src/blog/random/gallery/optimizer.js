import { parentPort } from "node:worker_threads";
import config from "#utils/config.js";
import path from "node:path";
import { importPSD } from "./Optimize.js";
import { readFile, mkdir, copyFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import crypto from "node:crypto";
import { exit } from "node:process";

const imageCache = path.join(config.cacheRoot, "optimized-images");
let processing = 0;
let waiting = 0;
let finished = false;

function shouldExit() {
    return processing == 0 && waiting == 0 && finished;
}

parentPort.on('message', async (data) => {
    if (data === "done") {
        finished = true;
        console.log("worker acknowledge");
        if (shouldExit()) {
            console.log("no more work.");
            console.log("exiting on reqeust");
            exit(0);
        } else {
            console.log("work still left in queue.");
        }
    } else {
        const { file, sizes, formats } = data;
        waiting += 1;
        while (processing > 1) {
            await new Promise((resolve, reject) => setTimeout(resolve, 500));
        }
        processing += 1;
        waiting -= 1;

        const bytes = await readFile(file);
        const hash = crypto.createHash('md5').update(bytes).digest('hex');
        const cache = path.join(imageCache, hash);
        const extname = path.extname(file);
        const basename = path.basename(file, extname);

        await mkdir(cache, { recursive: true });
        for (const [width, height] of sizes) {
            for (const format of formats) {
                const img = `${width}x${height}.${format.toLowerCase()}`;
                const cached = path.join(cache, img);
                const meta = `${basename}.${format} ${width}.${height}`;
                if (!existsSync(cached)) {
                    console.log(`generating ${meta}`);
                    const psd = await importPSD(file);
                    const options = {
                        format,
                        width,
                        height,
                        quality: 70,
                        metadata: false,
                        overridePath: cached,
                    };
                    // if (extname === ".psd") {
                    //     options.dpi = 300;
                    // }
                    await psd.process(options);
                }

                const resized = path.join(config.buildRoot, "optimized-images", basename, img);
                await mkdir(path.dirname(resized), { recursive: true });
                await copyFile(cached, resized);
            }
        }

        processing -= 1;
        if (processing == 0 && waiting == 0 && finished) {
            console.log("worker done");
            exit(0);
        }
    }
});

