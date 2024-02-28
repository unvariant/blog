import * as fs from "node:fs/promises";
import React from "react";
import { renderToString } from "react-dom/server";
import { execSync } from "node:child_process";
import * as path from "node:path";
import { Feed } from "feed";
import components from "./components.js"
import { $ } from "zx";
import hljs from 'highlight.js/lib/core';
import languages from "./languages.js";

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
    const { default: Content, ...frontMatter } = result;

    let element = React.createElement(Content, {
        ...options,
        ...frontMatter,
        components,
    });
    if (typeof frontMatter.layout === "string") {
        // console.log(`frontMatter: ${JSON.stringify(frontMatter)}`);
        const { default: layout, ...layoutFrontMatter } = await import(`file:///${cwd}/${frontMatter.layout}`);
        element = React.createElement(layout, {
            children: element,
            childFrontMatter: frontMatter,
            childOptions: options,
            // ...layoutFrontMatter,
        });
    }

    const rendered = renderToString(element);
    return { rendered, element };
};

for (const [langname, langdef] of Object.entries(languages)) {
    hljs.registerLanguage(langname, langdef);
}
const highlight = async (info, parentInfo, lang) => {
    const source = (await fs.readFile(info.sourcePath)).toString();
    let html;
    if (languages.hasOwnProperty(lang)) {
        html = hljs.highlight(source, { language: lang }).value;
    } else {
        html = source;
        lang = "text";
    }
    let element = React.createElement(components.pre, {
        always: true,
        filename: info.filename,
        children: (
            <code className={ `hljs language-${lang}` } dangerouslySetInnerHTML={{ __html: html }}>
            </code>
        ),
    });
    const { default: layout } = await import(`file:///${cwd}/src/page.mdx`);
    element = React.createElement(layout, {
        children: element,
        childFrontMatter: {},
        childOptions: {
            info,
            parentInfo,
        },
    });
    const rendered = renderToString(element);
    return { rendered, element };
};

const infoMemo = new Map();

const getInfo = async (relativePath) => {
    const sourcePath = path.join(blogRoot, relativePath);
    const normalized = path.normalize(path.relative(blogRoot, sourcePath));

    if (infoMemo.has(normalized)) {
        return infoMemo.get(normalized);
    } else {
        const extname = path.extname(relativePath);
        const filename = path.basename(relativePath);
        const basename = path.basename(relativePath, extname);
        const relativeParent = path.dirname(relativePath);
        const buildPath = path.join(builddir, relativePath);
        const stats = await fs.lstat(sourcePath);
        let lastModifiedDate;
        let size;
        let children = [];

        if (normalized.startsWith("..")) {
            lastModifiedDate = new Date(0);
            size = 0;
        } else {
            const log = await $`git log -1 --pretty="format:%cD" ${sourcePath}`;
            lastModifiedDate = new Date(log.stdout.trim());
            if (stats.isDirectory()) {
                const fd = (await $`fd -d 1 . '${sourcePath}'`).stdout.trim();
                children = await Promise.all(
                    fd.length > 0 ? fd.split("\n").map(file => {
                        return getInfo(path.relative(blogRoot, file))
                    }) : []
                );
                size = children.map(i => i.size).concat([0, 0]).reduce((a, b) => a + b);
            } else {
                size = stats.size;
            }
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
        infoMemo.set(normalized, info);
        return info;
    }
};

const yank = async (relativePath, parentInfo) => {
    const info = await getInfo(relativePath);

    let results;
    if (info.stats.isFile()) {
        switch (info.extname.toLowerCase()) {
            case ".md":
            case ".mdx":
                results = await mdxToHtml(info.sourcePath, {
                    info,
                    parentInfo,
                });
                addFeedItem({
                    title: info.basename,
                    url: info.relativePath,
                    content: results.rendered,
                });
                break;
            case ".c":
                results = await highlight(info, parentInfo, "c");
                break;
            case ".txt":
                results = await highlight(info, parentInfo, "text");
                break;
            default:
                switch (info.basename.toLowerCase()) {
                    case "makefile":
                        results = await highlight(info, parentInfo, "makefile");
                        break;
                    case "dockerfile":
                        results = await highlight(info, parentInfo, "dockerfile");
                        break;
                    default:
                        results = { rendered: await fs.readFile(info.sourcePath) };
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
                        noDefaultFolders: true,
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
            parentInfo,
        });
    } else {
        return;
    }

    console.log(`relativePath: ${info.relativePath}`);

    const outfile = path.join(builddir, relativePath, "index.html");
    const outdir = path.dirname(outfile);
    await fs.mkdir(outdir, { recursive: true });
    await fs.writeFile(outfile, results.rendered);
    return { info, ...results };
};

const buildSteps = [
    yank(".", await getInfo("..")),
    fs.cp("static", path.join(builddir), { recursive: true }),
];
await Promise.all(buildSteps);

await fs.writeFile(path.join(builddir, "feed.xml"), feed.rss2());