import * as fs from "node:fs/promises";
import React from "react";
import { renderToString } from "react-dom/server";
import { execSync } from "node:child_process";
import * as path from "node:path";
import { Feed } from "feed";
import components from "./components.js"

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

const yank = async (relativePath, stats, extraProps) => {
    const absolute = path.join(cwd, blogRoot, relativePath);
    const blogRelative = path.join(blogRoot, relativePath);
    const extname = path.extname(relativePath);
    const basename = path.basename(relativePath, extname);
    const filename = path.basename(relativePath);
    const relativeParent = path.dirname(relativePath);
    const options = extraProps || {};

    let results;
    let outFile;
    if (stats.isFile()) {
        switch (extname.toLowerCase()) {
            case ".md":
            case ".mdx":
                results = await mdxToHtml(blogRelative, { ...options });
                outFile = path.join(buildDir, relativeParent, `${filename}.html`);
                addFeedItem({
                    title: basename,
                    url: outFile,
                    content: results.rendered,
                });
                break;
            default:
                results = { rendered: await fs.readFile(absolute) };
                outFile = path.join(buildDir, relativePath);
                break;
        }
    } else if (stats.isDirectory()) {
        const fd = execSync(`fd -d 1 . '${blogRelative}'`, { encoding: "utf8" }).trim();
        const children = await Promise.all(
            fd.length > 0 ? fd.split("\n").map(async (file) => {
                const stats = await fs.lstat(file);
                stats.name = path.basename(file);
                stats.path = path.relative(blogRoot, file);
                return stats;
            }) : []
        );

        let readme;
        await Promise.all(
            children.map(async (entry) => {
                const results = await yank(path.join(relativePath, entry.name), entry);
                if (entry.name.toLowerCase().startsWith("readme")) {
                    let { props, ...stuff } = results.element;
                    readme = {
                        ...stuff,
                        props: {
                            ...props,
                            noDefaultFolders: true,
                        }
                    };
                }
            })
        );

        results = await mdxToHtml("src/index.mdx", {
            ...options,
            fileList: children,
            readme: readme,
        });
        outFile = path.join(buildDir, relativePath, "index.html");
    } else {
        return;
    }

    console.log(`relativePath: ${relativePath}`);
    const outdir = path.dirname(outFile);
    await fs.mkdir(outdir, { recursive: true });
    await fs.writeFile(outFile, results.rendered);
    return results;
};

const buildSteps = [
    yank(".", await fs.lstat(".")),
    fs.cp("static", path.join(buildDir), { recursive: true }),
];
await Promise.all(buildSteps);

await fs.writeFile(path.join(buildDir, "feed.xml"), feed.rss2());