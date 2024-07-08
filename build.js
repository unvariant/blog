import fs from "node:fs/promises";
import { getInfo } from "./src/utils/info.js";
import config from "./src/utils/config.js";
import { register } from "./processor.js";
import { execSync } from "node:child_process";
import Highlight from "./src/components/Highlight.js";
import { render, mdxToHtml } from './render.js';
import path from "node:path";
import crypto from "node:crypto";

async function highlight(info, lang) {
    const element = (
        <Highlight lang={ lang } info={ info } always>
        </Highlight>
    );
    
    return element;
}

function handleLanguage(lang) {
    return async function (info) {
        return await highlight(info, lang);
    };
}

const readelfCache = path.join(config.cacheRoot, "readelf-cache");
fs.mkdir(readelfCache, { recursive: true });

async function cachedElfInfo(info) {
    const value = info.source;
    const key = crypto.createHash('md5').update(value).digest('hex');
    const cached = path.join(readelfCache, key);

    try {
        return await fs.readFile(cached, { encoding: "utf-8" });
    } catch (e) {
        const readelf = execSync(`readelf -hldS ${info.absolutePath}`, { encoding: "utf-8" }).trim();
        await fs.writeFile(cached, readelf);
        return readelf;
    }
}

async function cachedModInfo(info) {
    const value = info.source;
    const key = crypto.createHash('md5').update(value).digest('hex');
    const cached = path.join(readelfCache, key);

    try {
        return await fs.readFile(cached, { encoding: "utf-8" });
    } catch (e) {
        const modinfo = execSync(`readelf -p .modinfo ${info.absolutePath}`, { encoding: "utf-8" }).trim();
        await fs.writeFile(cached, modinfo);
        return modinfo;
    }
}

register([ ".md", ".mdx", ], mdxToHtml);
register([ ".h", ".c", ], handleLanguage("c"));
register([ ".hpp", ".cpp" ], handleLanguage("cpp"));
register([ ".txt" ], handleLanguage("text"));
register([ ".zig", ".rs" ], handleLanguage("rs"));
register([ ".yml", ".yaml" ], handleLanguage("yaml"));
register([ ".ini", ".toml" ], handleLanguage("ini"));
register([ ".sh" ], handleLanguage("shell"));
register([ ".py" ], handleLanguage("python"));
register([ ".js" ], handleLanguage("js"));
register([ ".makefile" ], handleLanguage("makefile"));
register([ ".dockerfile" ], handleLanguage("dockerfile"));
register([ ".ko" ], async function (info) {
    let modinfo = await cachedModInfo(info);
    return (
        <div>
            <Highlight lang="text" source={ modinfo } filename="modinfo" open="true">
            </Highlight>
        </div>
    );
});
register([ ".elf" ], async function (info) {
    let readelf = await cachedElfInfo(info);
    // let checksec = (await $`pwn checksec ${info.sourcePath}`).stderr.trim();
    // checksec = checksec.substring(checksec.indexOf("\n") + 1);
    let checksec = "not available";
    
    return (
        <div>
            <Highlight lang="text" source={ checksec } filename="checksec" open="true">
            </Highlight>
            <Highlight lang="text" source={ readelf } filename="readelf" open="true">
            </Highlight>
        </div>
    );
});

export class Builder {
    constructor() {
        this.rootInfo = getInfo(config.blogRoot);
    }

    async renderAll() {
        await render(this.rootInfo);
    }
}

const builder = new Builder();
await fs.cp("static", config.buildRoot, { recursive: true })
await builder.renderAll();