import fs from "node:fs/promises";
import { getInfo } from "./src/utils/info.js";
import config from "./src/utils/config.js";
import { register } from "./processor.js";
import { execSync } from "node:child_process";
import Highlight from "./src/components/Highlight.js";
import { render, mdxToHtml } from './render.js';

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
    let modinfo = execSync(`readelf -p .modinfo ${info.absolutePath}`, { encoding: "utf-8" }).trim();
    return (
        <div>
            <Highlight lang="text" source={ modinfo } filename="modinfo" open="true">
            </Highlight>
        </div>
    );
});
register([ ".elf" ], async function (info) {
    let readelf = execSync(`readelf -hldS ${info.absolutePath}`, { encoding: "utf-8" }).trim();
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
        this.queue = [this.rootInfo];
    }

    async renderAll() {
        while (this.queue.length > 0) {
            const info = this.queue.at(-1);
            // console.log(`${info.relativePath} at ${info.resolved}, needs ${info.children.length}`);
            if (info.resolved == info.children.length) {
                // console.log(`rendering ${info.relativePath}`);
                await render(info);
                this.queue.pop();
            }
            if (info.pushChildren) {
                info.pushChildren = false;
                for (const child of info.children) {
                    this.queue.push(child);
                }
            }
        }
    }
}

const builder = new Builder();
await fs.cp("static", config.buildRoot, { recursive: true })
await builder.renderAll();