import * as path from "node:path";
import { execSync } from "node:child_process";
import fs from "node:fs/promises";
import { existsSync } from "node:fs";

export function getAbsolutePath(file) {
    return path.join(file.dir, file.base);
}

export async function getCachedDates() {
    if (existsSync(cached_date_file)) {
        const dates = JSON.parse(await fs.readFile(cached_date_file, { encoding: "utf-8" }));
        return dates;
    } else {
        const dates = {};
        for (const file of files) {
            const absolutePath = getAbsolutePath(file);
            const lastModifiedDate = new Date(
                execSync(`git log -1 --pretty="format:%cD" ${absolutePath}`, {
                    encoding: "utf-8",
                })
            );
            dates[absolutePath] = lastModifiedDate;
        }
        return dates;
    }
}

export async function setCachedDates(dates) {
    await fs.writeFile(cached_date_file, JSON.stringify(dates));
}

const cwd = path.resolve("");
const blogRoot = path.resolve(cwd, "src/blog");
const buildRoot = path.resolve(cwd, "_build");
const cached_date_file = path.join("_cache", "cached_dates.json");
await fs.mkdir(path.dirname(cached_date_file), { recursive: true });
const files = execSync(`fd --hidden . '${blogRoot}'`, { encoding: "utf-8" })
    .trim()
    .split("\n")
    .filter((s) => s.length > 0)
    .map((file) => path.parse(file));
const dates = await getCachedDates();

export default {
    cwd,
    blogRoot,
    buildRoot,
    files,
    dates,
};
