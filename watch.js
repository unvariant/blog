import nodemon from "nodemon";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { yank } from "./yank.js";
import { getInfo } from "./src/utils/info.js";
import config from "./src/utils/config.js";

async function update(info) {
    await yank(getInfo(info.absolutePath, false));
    if (info.parent) {
        await yank(getInfo(info.parent.absolutePath, false));
    }
}

const ignore = (await fs.readFile(".gitignore", { encoding: "utf-8" }))
    .split("\n")
    .filter(s => s.length > 0);

const watch = nodemon({
    ignore,
    watch: ["src/", "static/"],
}).on("restart", async files => {
    for (const file of files) {
        const rootRelative = path.relative(config.cwd, file);
        if (rootRelative.startsWith("static")) {
            await fs.cp("static", config.buildRoot, { recursive: true });
        } else if (rootRelative.startsWith("src/blog/")) {
            console.log(`reloading ${rootRelative}`);
            await update(getInfo(file));
        } else {
            console.log(`reloading ${rootRelative}`);
            await yank(getInfo(config.blogRoot, false));
        }
    }
});

await Promise.all([
    yank(getInfo(config.blogRoot)),
    fs.cp("static", config.buildRoot, { recursive: true }),
]);
console.log(`rebuilt blog`);

import.meta.hot?.accept(["./yank.js"]);