import * as fs from "node:fs/promises";
import React from "react";
import { renderToString } from "react-dom/server";
import { execSync } from "node:child_process";
import * as path from "node:path";
import { Feed } from "feed";
import { $ } from "zx";
import { fileTypeFromBuffer } from "file-type";
import NodeBuffer from "node:buffer";
import components from "./src/components.js"
import hljs from "./src/languages.js";
import Highlight from "./src/components/Highlight.js";
import Page from "./src/page.mdx";

$.verbose = false;

// for building on cf pages, they do a shallow clone by default which
// breaks the git log dates, so set build command to git fetch --unshallow && npm run build

const cwd = path.resolve("");
const blogRoot = path.normalize("src/blog");
const builddir = path.resolve("build");

const feed = new Feed({
    title: "feeed title",
    description: "tbd",
    link: "http://localhost:5500/",
    language: "en",
    generator: "generic",
    author: {
        name: "unvariant",
    }
});

const addFeedItem = (post) => {
    feed.addItem({
        title: post.title,
        id: post.url,
        link: post.url,
        description: "generic",
        content: post.content,
        author: [
            {
                name: "unvariant",
            },
        ],
    });
};

const mdxToHtml = async (sourcePath, options) => {
    const result = await import(`file:///${cwd}/${sourcePath}`);
    const { default: Content, ...props } = result;

    let element = React.createElement(Content, {
        ...options,
        ...props,
        components,
    });
    if (typeof props.layout === "string") {
        // console.log(`frontMatter: ${JSON.stringify(frontMatter)}`);
        const { default: layout } = await import(`file:///${cwd}/${props.layout}`);
        element = React.createElement(layout, {
            children: element,
        });
    }

    const rendered = renderToString(element);
    return { rendered, element };
};

const highlight = async (info, lang) => {
    const element = (
        <Page>
            <Highlight lang={ lang } info={ info } always="true">
            </Highlight>
        </Page>
    );
    
    const rendered = renderToString(element);
    return { rendered, element };
};

const infoMemo = new Map();

const getInfo = async (relativePath) => {
    relativePath = path.normalize(relativePath);
    const sourcePath = path.join(blogRoot, relativePath);
    const relativeParent = path.normalize(path.relative(blogRoot, path.join(relativePath, "..")));

    // console.log(relativePath, sourcePath);

    if (infoMemo.has(relativePath)) {
        return infoMemo.get(relativePath);
    } else {
        const extname = path.extname(relativePath);
        const filename = path.basename(relativePath);
        const basename = path.basename(relativePath, extname);
        const buildPath = path.join(builddir, relativePath);
        const stats = await fs.lstat(sourcePath);
        let lastModifiedDate;
        let size;
        let children = [];

        const log = await $`git log -1 --pretty="format:%cD" ${sourcePath}`;
        lastModifiedDate = new Date(log.stdout.trim());
        if (stats.isDirectory()) {
            console.log(`sourcePath: ${sourcePath}`);
            const fd = (await $`fd -d 1 . '${sourcePath}'`).stdout.trim();
            children = await Promise.all(
                fd.length > 0 ? fd.split("\n").map(file => {
                    const relativePath = path.relative(blogRoot, file);
                    console.log(`file: ${relativePath}`);
                    return getInfo(relativePath);
                }) : []
            );
            size = children.map(i => i.size).concat([0, 0]).reduce((a, b) => a + b);
        } else {
            size = stats.size;
        }

        if (relativePath.startsWith("..")) {
            lastModifiedDate = new Date(0);
            size = 0;
        }

        if (isNaN(lastModifiedDate)) {
            lastModifiedDate = new Date(0);
        }

        const info =  {
            stats,
            extname,
            filename,
            basename,
            relativePath,
            relativeParent,
            buildPath,
            sourcePath,
            lastModifiedDate,
            size,
            children,
        };

        for (const child of children) {
            child.parentInfo = info;
        }

        infoMemo.set(relativePath, info);

        return info;
    }
};

const yank = async (relativePath) => {
    const info = await getInfo(relativePath);

    let results;
    if (info.stats.isFile()) {
        const extname = info.extname.toLowerCase();
        const basename = info.basename.toLowerCase();
        switch (extname) {
            case ".md":
            case ".mdx":
                results = await mdxToHtml(info.sourcePath, {
                    info,
                });
                addFeedItem({
                    title: info.basename,
                    url: info.relativePath,
                    content: results.rendered,
                });
                break;
            case ".h":
            case ".c":
                results = await highlight(info, "c");
                break;
            case ".hpp":
            case ".cpp":
                results = await highlight(info, "cpp");
                break;
            case ".txt":
                results = await highlight(info, "text");
                break;
            case ".zig":
            case ".rs":
                results = await highlight(info, "rs");
                break;
            case ".yml":
            case ".yaml":
                results = await highlight(info, "yaml");
                break;
            case ".ini":
            case ".toml":
                results = await highlight(info, "ini");
                break;
            case ".ko":
                let modinfo = (await $`readelf -p .modinfo ${info.sourcePath}`).stdout.trim();
                const element = (
                    <Page>
                        <div info={ info }>
                            <Highlight lang="text" source={ modinfo } filename="modinfo" open="true">
                            </Highlight>
                        </div>
                    </Page>
                );
                results = { rendered: renderToString(element), element };
                break;
            case ".sh":
                results = await highlight(info, "shell");
                break;
            case ".py":
                results = await highlight(info, "python");
                break;
            default:
                switch (info.basename.toLowerCase()) {
                    case "makefile":
                        results = await highlight(info, "makefile");
                        break;
                    case "dockerfile":
                        results = await highlight(info, "dockerfile");
                        break;
                    default:
                        const source = await fs.readFile(info.sourcePath);
                        const type = await fileTypeFromBuffer(source);
                        results = { rendered: source };
                        if (type) {
                            switch (type.ext) {
                                case "elf":
                                    let readelf = (await $`readelf -hldS ${info.sourcePath}`).stdout.trim();
                                    // let checksec = (await $`pwn checksec ${info.sourcePath}`).stderr.trim();
                                    // checksec = checksec.substring(checksec.indexOf("\n") + 1);
                                    let checksec = "not currently available";
                                    
                                    const element = (
                                        <Page>
                                            <div info={ info }>
                                                <Highlight lang="text" source={ checksec } filename="checksec" open="true">
                                                </Highlight>
                                                <Highlight lang="text" source={ readelf } filename="readelf" open="true">
                                                </Highlight>
                                            </div>
                                        </Page>
                                    );
                                    results = { rendered: renderToString(element), element };
                                    break;
                            } 
                        } else if (NodeBuffer.isUtf8(source)) {
                            const element = (
                                <Page>
                                    <div info={ info }>
                                        <Highlight lang="text" source={ source.toString() } filename={ info.filename } always>
                                        </Highlight>
                                    </div>
                                </Page>
                            );
                            results = { rendered: renderToString(element), element };
                        }
                        break;
                }
                break;
        }
    } else if (info.stats.isDirectory()) {
        let readme;
        await Promise.all(info.children.map(async childInfo => {
            const results = await yank(childInfo.relativePath, info);
            if (childInfo.basename.toLowerCase().startsWith("readme")) {
                let { props, ...stuff } = results.element;
                readme = {
                    ...stuff,
                    props: {
                        ...props,
                        embed: true,
                    }
                };
            }
        }));

        // const children = await Promise.all(
        //     info.children.map(async (relativePath) => {
        //         const results = await yank(relativePath, info);
        //         if (results.info.basename.toLowerCase().startsWith("readme")) {
        //             let { props, ...stuff } = results.element;
        //             readme = {
        //                 ...stuff,
        //                 props: {
        //                     ...props,
        //                     noDefaultFolders: true,
        //                 }
        //             };
        //         }
        //         return results.info;
        //     })
        // );

        results = await mdxToHtml("src/index.mdx", {
            fileList: info.children,
            readme,
            info,
        });
    } else {
        return;
    }

    console.log(`relativePath: ${info.relativePath}`);

    const outfile = path.join(builddir, info.relativePath, "index.html");
    const outdir = path.dirname(outfile);
    await fs.mkdir(outdir, { recursive: true });
    await fs.writeFile(outfile, results.rendered);
    if (info.stats.isFile()) {
        const outraw = path.join(builddir, info.relativePath, "raw");
        await fs.copyFile(info.sourcePath, outraw);
    }
    return { info, ...results };
};

await getInfo("..");

const buildSteps = [
    yank("."),
    fs.cp("static", path.join(builddir), { recursive: true }),
];
await Promise.all(buildSteps);

await fs.writeFile(path.join(builddir, "feed.xml"), feed.rss2());