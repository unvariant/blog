import { parentPort } from "node:worker_threads";
import config from "../../../utils/config.js";
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

parentPort.on('message', async (data) => {
    if (data === "done") {
        finished = true;
        console.log("worker acknowledge");
    } else {
        const { file, sizes, formats } = data;
        waiting += 1;
        while (processing > 1) {
            await new Promise((resolve, reject) => setTimeout(resolve, 500));
        }
        waiting -= 1;
        processing += 1;

        const bytes = await readFile(file);
        const hash = crypto.createHash('md5').update(bytes).digest('hex');
        const cache = path.join(imageCache, hash);
        const extname = path.extname(file);
        const basename = path.basename(file, extname);

        await mkdir(cache, { recursive: true });
        for (const size of sizes) {
            for (const format of formats) {
                const img = `${size}x${size}.${format.toLowerCase()}`;
                const cached = path.join(cache, img);

                if (!existsSync(cached)) {
                    console.log(`generating ${path.basename(file)}.${format} ${size}.${size}`);
                    const psd = await importPSD(file);
                    const options = {
                        format,
                        width: size,
                        height: size,
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

