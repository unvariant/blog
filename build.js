import * as path from "node:path";
import * as fs from "node:fs/promises";
import { getInfo } from "./src/utils/info.js";
import config from "./src/utils/config.js";
import { register, process } from "./processor.js";
import { fileTypeFromBuffer } from "file-type";

import React from "react";
import { renderToString } from "react-dom/server";
import { execSync } from "node:child_process";
import NodeBuffer from "node:buffer";
import componentMap from "./src/components.js"
import Highlight from "./src/components/Highlight.js";
import Page from "./src/components/Page.js";
import { InfoContext } from "./src/components/InfoContext.js";

function withInfo(info, element) {
    return (
        <InfoContext.Provider value={ info }>
            { element }
        </InfoContext.Provider>
    );
}

async function mdxToHtml(info, options) {
    const importUrl = `file:///${info.absolutePath}?t=${info.reloadCount}`;
    const result = await import(importUrl);
    const { default: Content, ...props } = result;

    const element = React.createElement(Content, {
        ...options,
        ...props,
        components: componentMap,
    });

    return element;
}

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
    let checksec = "not currently available";
    
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
            const info = this.queue.shift();
            if (info.pushChildren) {
                info.pushChildren = false;
                for (const child of info.children) {
                    this.queue.push(child);
                }
            }
            if (info.resolved == info.children.length) {
                await this.render(info);
            } else {
                this.queue.push(info);
            }
        }
    }

    async render(info) {
        let element = undefined;
        if (info.stats.isFile()) {
            const extname = info.extname.toLowerCase();
            element = await process(extname, info, async function (info) {
                switch (info.basename.toLowerCase()) {
                    case "makefile":
                        return process("makefile", info);
                    case "dockerfile":
                        return process("dockerfile", info);
                    default:
                        const type = await fileTypeFromBuffer(info.source);
                        if (type) {
                            switch (type.ext) {
                                case "elf":
                                    return process("elf", info);
                            }
                        }

                        if (NodeBuffer.isUtf8(info.source)) {
                            return (
                                <div>
                                    <Highlight lang="text" source={ info.source.toString() } filename={ info.filename } always>
                                    </Highlight>
                                </div>
                            );
                        }
                }
            });
        } else if (info.stats.isDirectory()) {
            if (info.resolved == info.children.length) {
                let readme;
                for (const child of info.children) {
                    if (child.stats.isFile() && child.basename.toLowerCase().startsWith("readme")) {
                        readme = child.element;
                    }
                }
                
                element = await mdxToHtml(getInfo(path.resolve(config.cwd, "src/index.mdx")), {
                    readme,
                });
            }
        } else if (info.stats.isSymbolicLink()) {
            const target = await fs.readlink(info.absolutePath);
            element = (
                <div>
                    <p>
                        { "symbolic link to " }
                        <a href={ `../${target}` }>{ target }</a>
                    </p>
                </div>
            );
        }

        if (info.resolved == info.children.length) {
            if (element === undefined) {
                element = (
                    <div>
                        <p>
                            { "cannot view binary file. go to raw/ to download instead" }
                        </p>
                    </div>
                );
            }
        
            element = withInfo(info, element);

            info.parent.resolved += 1;
            info.parent.size += info.size;
            info.element = element;

            const page = (
                <InfoContext.Provider value={ info }>
                    <Page>
                        { element }
                    </Page>
                </InfoContext.Provider>
            );
            const rendered = renderToString(page);
            const outfile = path.join(config.buildRoot, info.relativePath, "index.html");
            const outdir = path.dirname(outfile);

            if (info.relativePath.startsWith("..")) {
                console.log(info.relativePath);
                throw new Error("wtf??");
            }

            await fs.mkdir(outdir, { recursive: true });
            await fs.writeFile(outfile, rendered);
            if (info.stats.isFile()) {
                const outraw = path.join(config.buildRoot, info.relativePath, "raw");
                if (info.stats.size < 20 * 1024 * 1024) {
                    await fs.copyFile(info.absolutePath, outraw);
                } else {
                    const repoRelativePath = path.relative(config.cwd, info.absolutePath);
                    const route = path.normalize(path.join("unvariant/blog/main/", repoRelativePath));
                    const redirect = (
                        <html>
                            <head>
                                <meta httpEquiv="refresh" content={ `0; url=https://raw.githubusercontent.com/${route}` } />
                            </head>
                            <body>
                                <p>
                                    { "sorry this file too large for cloudflare pages, redirecting to github instead." }
                                </p>
                            </body>
                        </html>
                    );
                    const html = renderToString(redirect);
                    await fs.writeFile(outraw, html);
                }
            }
        }
    }
}

const builder = new Builder();
const buildSteps = [
    builder.renderAll(),
    fs.cp("static", path.join(config.buildRoot), { recursive: true }),
];
await Promise.all(buildSteps);