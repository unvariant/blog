import * as fs from "node:fs/promises";
import React from "react";
import { renderToString } from "react-dom/server";
import { execSync } from "node:child_process";
import * as path from "node:path";
import { Feed } from "feed";
import { fileTypeFromBuffer } from "file-type";
import NodeBuffer from "node:buffer";
import componentMap from "./src/components.js"
import hljs from "./src/languages.js";
import Highlight from "./src/components/Highlight.js";
import Page from "./src/components/Page.js";
import { InfoContext } from "./src/components/InfoContext.js";
import { getInfo } from "./src/utils/info.js";
import config from "./src/utils/config.js";

// for building on cf pages, they do a shallow clone by default which
// breaks the git log dates, so set build command to git fetch --unshallow && npm run build

// const feed = new Feed({
//     title: "feeed title",
//     description: "tbd",
//     link: "http://localhost:5500/",
//     language: "en",
//     generator: "generic",
//     author: {
//         name: "unvariant",
//     }
// });

// const addFeedItem = (post) => {
//     feed.addItem({
//         title: post.title,
//         id: post.url,
//         link: post.url,
//         description: "generic",
//         content: post.content,
//         author: [
//             {
//                 name: "unvariant",
//             },
//         ],
//     });
// };

function withInfo(info, element) {
    return (
        <InfoContext.Provider value={ info }>
            { element }
        </InfoContext.Provider>
    );
}

async function mdxToHtml(info, options) {
    const result = await import(`file:///${info.absolutePath}`);
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
        <Highlight lang={ lang } info={ info } always="true">
        </Highlight>
    );
    
    return element;
}

async function yank(info) {
    let element = undefined;
    if (info.stats.isFile()) {
        const extname = info.extname.toLowerCase();
        const basename = info.basename.toLowerCase();
        switch (extname) {
            case ".md":
            case ".mdx":
                element = await mdxToHtml(info, {
                    info,
                });
                break;
            case ".h":
            case ".c":
                element = await highlight(info, "c");
                break;
            case ".hpp":
            case ".cpp":
                element = await highlight(info, "cpp");
                break;
            case ".txt":
                element = await highlight(info, "text");
                break;
            case ".zig":
            case ".rs":
                element = await highlight(info, "rs");
                break;
            case ".yml":
            case ".yaml":
                element = await highlight(info, "yaml");
                break;
            case ".ini":
            case ".toml":
                element = await highlight(info, "ini");
                break;
            case ".ko":
                let modinfo = execSync(`readelf -p .modinfo ${info.absolutePath}`, { encoding: "utf-8" }).trim();
                element = (
                    <div>
                        <Highlight lang="text" source={ modinfo } filename="modinfo" open="true">
                        </Highlight>
                    </div>
                );
                break;
            case ".sh":
                element = await highlight(info, "shell");
                break;
            case ".py":
                element = await highlight(info, "python");
                break;
            default:
                switch (info.basename.toLowerCase()) {
                    case "makefile":
                        element = await highlight(info, "makefile");
                        break;
                    case "dockerfile":
                        element = await highlight(info, "dockerfile");
                        break;
                    default:
                        const source = info.source;
                        const type = await fileTypeFromBuffer(source);
                        if (type) {
                            switch (type.ext) {
                                case "elf":
                                    let readelf = execSync(`readelf -hldS ${info.absolutePath}`, { encoding: "utf-8" }).trim();
                                    // let checksec = (await $`pwn checksec ${info.sourcePath}`).stderr.trim();
                                    // checksec = checksec.substring(checksec.indexOf("\n") + 1);
                                    let checksec = "not currently available";
                                    
                                    element = (
                                        <div>
                                            <Highlight lang="text" source={ checksec } filename="checksec" open="true">
                                            </Highlight>
                                            <Highlight lang="text" source={ readelf } filename="readelf" open="true">
                                            </Highlight>
                                        </div>
                                    );
                                    break;
                            } 
                        } else if (NodeBuffer.isUtf8(source)) {
                            element = (
                                <div>
                                    <Highlight lang="text" source={ source.toString() } filename={ info.filename } always>
                                    </Highlight>
                                </div>
                            );
                        }
                        break;
                }
                break;
        }
    } else if (info.stats.isDirectory()) {
        let readme;
        await Promise.all(info.children.map(async child => {
            const results = await yank(child);
            if (child.stats.isFile() && child.basename.toLowerCase().startsWith("readme")) {
                readme = results;
            }
        }));

        element = await mdxToHtml(getInfo(path.resolve(config.cwd, "src/index.mdx")), {
            readme,
        });
    } else {
        throw new Error("unable to handle file");
    }

    if (element === undefined) {
        element = (
            <div>
                <Highlight lang="text" info={ info } always>
                </Highlight>
            </div>
        );
    }

    element = withInfo(info, element);

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
    await fs.mkdir(outdir, { recursive: true });
    await fs.writeFile(outfile, rendered);
    if (info.stats.isFile()) {
        const outraw = path.join(config.buildRoot, info.relativePath, "raw");
        await fs.copyFile(info.absolutePath, outraw);
    }
    return element;
};

const root = getInfo(config.blogRoot);
const buildSteps = [
    yank(root),
    fs.cp("static", path.join(config.buildRoot), { recursive: true }),
];
await Promise.all(buildSteps);

// await fs.writeFile(path.join(config.buildRoot, "feed.xml"), feed.rss2());