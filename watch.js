import nodemon from "nodemon";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { Builder } from "./build.js";
import { getInfo, removeInfo } from "./src/utils/info.js";
import config from "./src/utils/config.js";

const builder = new Builder();

async function update(info) {
    removeInfo(info.parent.absolutePath);
    removeInfo(info.absolutePath);
    builder.queue.push(getInfo(info.parent.absolutePath));
    for (const child of info.parent.children) {
        if (child.resolved == child.children.length) {
            
        }
    }
    builder.renderAll();
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
        }
    }
});

await Promise.all([
    builder.renderAll(),
    fs.cp("static", config.buildRoot, { recursive: true }),
]);
console.log(`rebuilt blog`);

import.meta.hot?.accept(["./build.js"]);