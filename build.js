import * as fs from "node:fs/promises";
import { compile, evaluate } from "@mdx-js/mdx";
import { MDXProvider } from "@mdx-js/react";
import * as runtime from "react/jsx-runtime";
import React from "react";
import { renderToString } from "react-dom/server";
import { execSync } from "node:child_process";
import * as path from "node:path";
// import { register } from "node:module";

// register("./loader.js", import.meta.url);

const cwd = path.resolve("");
const blogRoot = path.normalize("src/blog");
const buildDir = path.resolve("build");

const mdxToHtml = async (file, options) => {
    const result = await import(`file:///${cwd}/${file}`);
    const {default: Content, ...rest } = result;

    const element = React.createElement(Content, {
        ...options,
        ...rest,
    });
    
    const rendered = renderToString(element);
    return { rendered, element };
};

const compare = (a, b) => {
    if (a < b) {
        return -1;
    } else if (a > b) {
        return 1;
    } else {
        return 0;
    }
};

const isDirectory = (file) => {
    return file.endsWith("/");
};

const yank = async (relativePath, stats) => {
    const absolute = path.join(cwd, blogRoot, relativePath);
    const blogRelative = path.join(blogRoot, relativePath);
    const extname = path.extname(relativePath);
    const basename = path.basename(relativePath, extname);
    const relativeParent = path.dirname(relativePath);

    let results;
    let outFile;
    if (stats.isFile()) {
        switch (extname.toLowerCase()) {
            case ".md":
            case ".mdx":
                results = await mdxToHtml(blogRelative, {});
                outFile = path.join(buildDir, relativeParent, `${basename}${extname}`);
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
                let results = await yank(path.join(relativePath, entry.name), entry);
                if (entry.name.toLowerCase().startsWith("readme")) {
                    readme = results.element;
                }
            })
        );

        results = await mdxToHtml("src/index.mdx", { meta: {
            fileList: children,
            readme: readme,
        }});
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

yank(".", await fs.lstat("."));

// const files = execSync(`fd --base-directory ${blogRoot}`, { encoding: "utf8", })
//     .trim()
//     .split("\n")
//     .map(file => `./${file}`);
// files.push("./");
// files.sort();
// const directories = files.filter(isDirectory);
// const children = new Map();
// directories.forEach((dir) => {
//     let start = files.indexOf(dir) + 1;
//     const childFiles = [];
//     const childDirectories = [];
//     while (start < files.length && files[start].startsWith(dir)) {
//         const file = files[start];
//         if (isDirectory(file)) {
//             childDirectories.push(file);
//         } else {
//             childFiles.push(file);
//         }
//         start += 1;
//     }
//     children[dir] = {
//         childFiles,
//         childDirectories,
//     };
// });
// files.forEach(async (file) => {
//     const extname = path.extname(file);
//     const basename = path.basename(file, extname);
//     const relativeParent = path.dirname(file);

//     const filepath = path.join(blogRoot, file);
//     const absolute = path.resolve(filepath);
    
//     let content;
//     let outFile = path.join(buildDir, file);

//     if (directories.indexOf(file) >= 0) {
//         console.log(`${file} is a directory`);
//         content = await mdxToHtml("index.mdx", { meta: {
//             ...children[file],
//         }});
//         outFile = path.join(buildDir, file, "index.html");
//     } else {
//         console.log(`${file} is a normal file`);
//         switch (extname.toLowerCase()) {
//             case ".mdx":
//                 content = await mdxToHtml(filepath, { meta: {

//                 }});
//                 outFile = path.join(buildDir, relativeParent, `${basename}.html`);
//                 break;
//             default:
//                 content = await fs.readFile(absolute);
//                 outFile = path.join(buildDir, file);
//         }
//     }

//     const outdir = path.dirname(outFile);
//     await fs.mkdir(outdir, { recursive: true });
//     await fs.writeFile(outFile, content);
// });