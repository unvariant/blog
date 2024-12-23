import path from "node:path";
import fs from "node:fs/promises";
import { getInfo } from "./utils/info.js";
import config from "./utils/config.js";
import { register, process } from "./processor.js";
import { fileTypeFromBuffer } from "file-type";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { execSync } from "node:child_process";
import NodeBuffer from "node:buffer";
import componentMap from "./components.js";
import Highlight from "./components/Highlight.js";
import Page from "./components/Page.js";
import { InfoContext, PageContext } from "./components/Context.js";

async function unknownProcessor(info) {
    switch (info.basename.toLowerCase()) {
        case "makefile":
            return process("makefile", info);
        case "dockerfile":
            return process("dockerfile", info);
        default:
            if (
                info.source.subarray(0, 4).compare(Buffer.from("\x7fELF")) == 0
            ) {
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
                        <Highlight
                            lang="text"
                            source={info.source.toString()}
                            filename={info.filename}
                            always
                        ></Highlight>
                    </div>
                );
            }
    }
}

function withInfo(info, element) {
    return <InfoContext.Provider value={info}>{element}</InfoContext.Provider>;
}

function withPage(info, element) {
    return <PageContext.Provider value={info}>{element}</PageContext.Provider>;
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

export async function render(info, hooks) {
    let element = undefined;
    let layout = Page;

    for (const hook of hooks["preprocess"]) {
        hook(info);
    }

    if (info.stats.isFile()) {
        const extname = info.extname.toLowerCase();
        element = await process(extname, info, unknownProcessor);
    } else if (info.stats.isDirectory()) {
        let readme = <div></div>;
        const children = await Promise.all(
            info.children.map((i) => render(i, hooks))
        );
        for (const child of children) {
            if (child.stats.isFile()) {
                if (child.basename.toLowerCase().startsWith("readme")) {
                    readme = child.element;

                    if (child.requestedLayout) {
                        let layoutLink = `file:///${config.cwd}/${child.requestedLayout}`;
                        if (child.requestedLayout.startsWith("#")) {
                            layoutLink = child.requestedLayout;
                        }
                        const { default: Content, ...props } = await import(
                            layoutLink
                        );
                        layout = Content;
                    }
                }
            }
        }

        element = readme;
    } else if (info.stats.isSymbolicLink()) {
        const target = await fs.readlink(info.absolutePath);
        element = (
            <div>
                <p>
                    {"symbolic link to "}
                    <a href={`../${target}`}>{target}</a>
                </p>
            </div>
        );
    }

    if (element === undefined) {
        element = (
            <div>
                <p>
                    <span>{"cannot view binary file."}</span>
                </p>
                <p>
                    <a href="raw" download={info.filename}>
                        {"click to download instead."}
                    </a>
                </p>
            </div>
        );
    }

    for (const hook of hooks["prerender"]) {
        hook(info, element);
    }

    // capture layout before the element gets wrapped up
    const requestedLayout = element.props.layout;
    const props = element.props;
    element = withInfo(info, element);

    info.parent.size += info.size;
    info.element = element;
    info.requestedLayout = requestedLayout;

    const page = withPage(
        props,
        withInfo(
            info,
            React.createElement(layout, {
                children: element,
            })
        )
    );
    const rendered = renderToStaticMarkup(page);
    const outfile = path.join(
        config.buildRoot,
        info.relativePath,
        "index.html"
    );
    const outdir = path.dirname(outfile);

    if (info.relativePath.startsWith("..")) {
        console.log(info.relativePath);
        throw new Error("wtf??");
    }

    await fs.mkdir(outdir, { recursive: true });
    await fs.writeFile(outfile, rendered);
    if (info.stats.isFile()) {
        const outraw = path.join(config.buildRoot, info.relativePath, "raw");
        if (info.stats.size < config.fileSizeLimit) {
            await fs.copyFile(info.absolutePath, outraw);
        } else {
            const repoRelativePath = path.relative(
                config.cwd,
                info.absolutePath
            );
            const route = path.normalize(
                path.join("unvariant/blog/main/", repoRelativePath)
            );
            const redirect = (
                <html>
                    <head>
                        <meta
                            httpEquiv="refresh"
                            content={`0; url=https://raw.githubusercontent.com/${route}`}
                        />
                    </head>
                    <body>
                        <p>
                            {
                                "sorry this file too large for this hosting provider, redirecting to github instead."
                            }
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
