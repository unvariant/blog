import * as path from "node:path";
import { execSync } from "node:child_process";
import fs from "node:fs/promises";
import { existsSync } from "node:fs";

export function isDevelopmentMode() {
    return /(--dev)/.test(process.execArgv.join(' '));
}

export function getAbsolutePath(file) {
    return path.join(file.dir, file.base);
}

export async function getCachedDates() {
    if (isDevelopmentMode()) {
        return {};
    }

    if (existsSync(cachedDateFile)) {
        console.log(`[+] using cached dates ${cachedDateFile}`);
        const dates = JSON.parse(await fs.readFile(cachedDateFile, { encoding: "utf-8" }));
        return dates;
    } else {
        console.log(`[+] regenerating cached dates`);
        const dates = {};
        for (const file of files) {
            const absolutePath = getAbsolutePath(file);
            let lastModifiedDate = new Date(
                execSync(`git log -1 --pretty="format:%cD" ${absolutePath}`, {
                    encoding: "utf-8",
                })
            );
            if (isNaN(lastModifiedDate)) {
                lastModifiedDate = new Date(0);
            }
            dates[absolutePath] = lastModifiedDate;
        }
        await setCachedDates(dates);
        return dates;
    }
}

export async function setCachedDates(dates) {
    await fs.writeFile(cachedDateFile, JSON.stringify(dates));
}

const cwd = path.resolve("");
const blogRoot = path.resolve(cwd, "src/blog");
const buildRoot = path.resolve(cwd, "_build");
const cacheRoot = path.resolve("_cache"); 
const cachedDateFile = path.join(cacheRoot, "cached_dates.json");
await fs.mkdir(path.dirname(cachedDateFile), { recursive: true });
const files = execSync(`fd --hidden . '${blogRoot}'`, { encoding: "utf-8", maxBuffer: 1024 * 1024 * 4 })
    .trim()
    .split("\n")
    .filter((s) => s.length > 0)
    .concat([blogRoot])
    .map((file) => path.parse(file));
const dates = await getCachedDates();

export default {
    cwd,
    blogRoot,
    buildRoot,
    cacheRoot,
    files,
    dates,
};
