import * as fs from "node:fs/promises";
import React from "react";
import { renderToString } from "react-dom/server";
import { execSync } from "node:child_process";
import * as path from "node:path";
import { Feed } from "feed";
import components from "./components.js"
import { $ } from "zx";

// import { register } from "node:module";

// register("./loader.js", import.meta.url);

const cwd = path.resolve("");
const blogRoot = path.normalize("src/blog");
const buildDir = path.resolve("build");

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

const mdxToHtml = async (file, options) => {
    const result = await import(`file:///${cwd}/${file}`);
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
            // ...layoutFrontMatter,
        });
    }

    const rendered = renderToString(element);
    return { rendered, element };
};

const getInfo = async (relativePath) => {
    const extname = path.extname(relativePath);
    const filename = path.basename(relativePath);
    const basename = path.basename(relativePath, extname);
    const relativeParent = path.dirname(relativePath);
    const buildPath = path.join(buildDir, relativePath);
    const sourcePath = path.join(blogRoot, relativePath);
    const stats = await fs.lstat(sourcePath);
    const lastModifiedDate = new Date(await $`git log -1 --pretty="format:%cD" ${sourcePath}`);

    return {
        stats,
        extname,
        filename,
        basename,
        relativePath,
        relativeParent,
        buildPath,
        sourcePath,
        lastModifiedDate,
    };
};

const yank = async (relativePath) => {
    const absolute = path.join(cwd, blogRoot, relativePath);
    const blogRelative = path.join(blogRoot, relativePath);
    const extname = path.extname(relativePath);
    const basename = path.basename(relativePath, extname);
    const filename = path.basename(relativePath);
    const relativeParent = path.dirname(relativePath);

    const info = await getInfo(relativePath);

    let results;
    let outFile;
    if (info.stats.isFile()) {
        switch (info.extname.toLowerCase()) {
            case ".md":
            case ".mdx":
                results = await mdxToHtml(info.sourcePath);
                outFile = path.join(buildDir, info.relativeParent, `${info.filename}.html`);
                addFeedItem({
                    title: info.basename,
                    url: outFile,
                    content: results.rendered,
                });
                break;
            default:
                results = { rendered: await fs.readFile(info.sourcePath) };
                outFile = path.join(buildDir, info.relativePath);
                break;
        }
        info.size = results.rendered.length;
    } else if (info.stats.isDirectory()) {
        const fd = execSync(`fd -d 1 . '${info.sourcePath}'`, { encoding: "utf8" }).trim();
        const relativePaths = await Promise.all(
            fd.length > 0 ? fd.split("\n").map((file) => {
                return path.relative(blogRoot, file);
            }) : []
        );
        // const relativePaths = (await fs.readdir(info.sourcePath)).map(name => path.join(info.relativePath, name));

        let readme;
        const children = await Promise.all(
            relativePaths.map(async (relativePath) => {
                const results = await yank(relativePath);
                if (results.info.basename.toLowerCase().startsWith("readme")) {
                    let { props, ...stuff } = results.element;
                    readme = {
                        ...stuff,
                        props: {
                            ...props,
                            noDefaultFolders: true,
                        }
                    };
                }
                return results.info;
            })
        );

        results = await mdxToHtml("src/index.mdx", {
            fileList: children,
            readme: readme,
        });
        outFile = path.join(buildDir, info.relativePath, "index.html");
        info.size = children.map(i => i.size).concat([0]).reduce((a, b) => a + b);
    } else {
        return;
    }

    console.log(`relativePath: ${info.relativePath}`);

    const outdir = path.dirname(outFile);
    await fs.mkdir(outdir, { recursive: true });
    await fs.writeFile(outFile, results.rendered);
    return { info, ...results };
};

const buildSteps = [
    yank(".", await fs.lstat(".")),
    fs.cp("static", path.join(buildDir), { recursive: true }),
];
await Promise.all(buildSteps);

await fs.writeFile(path.join(buildDir, "feed.xml"), feed.rss2());