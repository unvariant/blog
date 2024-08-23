import path from "node:path";
import fs from "node:fs/promises";
import { getInfo } from "./src/utils/info.js";
import config from "./src/utils/config.js";
import { register, process } from "./processor.js";
import { fileTypeFromBuffer } from "file-type";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { execSync } from "node:child_process";
import NodeBuffer from "node:buffer";
import componentMap from "./src/components.js"
import Highlight from "./src/components/Highlight.js";
import Page from "./src/components/Page.js";
import { InfoContext } from "./src/components/InfoContext.js";

async function unknownProcessor(info) {
    switch (info.basename.toLowerCase()) {
        case "makefile":
            return process("makefile", info);
        case "dockerfile":
            return process("dockerfile", info);
        default:
            if (info.source.subarray(0, 4).compare(Buffer.from("\x7fELF")) == 0) {
                return process("elf", info);
            }
            // const type = await fileTypeFromBuffer(info.source);
            // if (type) {
            //     switch (type.ext) {
            //         case "elf":
            //             return process("elf", info);
            //     }
            // }

            if (NodeBuffer.isUtf8(info.source.subarray(0, 100))) {
                return (
                    <div>
                        <Highlight lang="text" source={ info.source.toString() } filename={ info.filename } always>
                        </Highlight>
                    </div>
                );
            }
    }
}

function withInfo(info, element) {
    return (
        <InfoContext.Provider value={ info }>
            { element }
        </InfoContext.Provider>
    );
}

export async function mdxToHtml(info, options) {
    const importUrl = `file:///${info.absolutePath}`;
    const result = await import(importUrl);
    const { default: Content, ...props } = result;

    const element = React.createElement(Content, {
        ...options,
        ...props,
        components: componentMap,
    });

    return element;
}

export async function render(info) {
    let element = undefined;
    let layout = Page;

    if (info.stats.isFile()) {
        const extname = info.extname.toLowerCase();
        element = await process(extname, info, unknownProcessor);
    } else if (info.stats.isDirectory()) {
        let readme = (
            <div></div>
        );
        const children = await Promise.all(info.children.map(render));
        for (const child of children) {
            if (child.stats.isFile() && child.basename.toLowerCase().startsWith("readme")) {
                readme = child.element;
                if (child.requestedLayout) {
                    const { default: Content, ...props } = await import(`file:///${config.cwd}/${child.requestedLayout}`);
                    layout = Content;
                }
            }
        }
        
        element = readme;
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

    if (element === undefined) {
        element = (
            <div>
                <p>
                    <span>{ "cannot view binary file." }</span>
                </p>
                <p>
                    <a href="raw" download={info.filename}>{ "click to download instead." }</a>
                </p>
            </div>
        );
    }

    // capture layout before the element gets wrapped up
    const requestedLayout = element.props.layout;
    element = withInfo(info, element);

    info.parent.size += info.size;
    info.element = element;
    info.requestedLayout = requestedLayout;

    const page = (
        <InfoContext.Provider value={ info }>
            { React.createElement(layout, {
                children: element,
            }) }
        </InfoContext.Provider>
    );
    const rendered = renderToStaticMarkup(page);
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
            const html = renderToStaticMarkup(redirect);
            await fs.writeFile(outraw, html);
        }
    }

    return info;
}