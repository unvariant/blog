import "react";
import fs from "node:fs/promises";
import { getInfo } from "./utils/info.js";
import config, { isDevelopmentMode, getCachedDates } from "./utils/config.js";
import { register } from "./processor.js";
import { execSync } from "node:child_process";
import Highlight from "./components/Highlight.js";
import { render, mdxToHtml } from "./render.js";
import path from "node:path";
import crypto from "node:crypto";
import { optimizer } from "./blog/random/gallery/handle.js";
import { SitemapStream, streamToPromise } from "sitemap";
import { Readable } from "node:stream";
import { Feed } from "feed";

async function highlight(info, lang) {
    const element = <Highlight lang={lang} info={info} always></Highlight>;
    return element;
}

function handleLanguage(lang) {
    return async function (info) {
        return await highlight(info, lang);
    };
}

const readelfCache = path.join(config.cacheRoot, "readelf-cache");
fs.mkdir(readelfCache, { recursive: true });

async function cachedElfInfo(info) {
    const value = info.source;
    const key = crypto.createHash("md5").update(value).digest("hex");
    const cached = path.join(readelfCache, key);

    try {
        return await fs.readFile(cached, { encoding: "utf-8" });
    } catch (e) {
        const readelf = execSync(`readelf -hldS ${info.absolutePath}`, {
            encoding: "utf-8",
        }).trim();
        await fs.writeFile(cached, readelf);
        return readelf;
    }
}

async function cachedModInfo(info) {
    const value = info.source;
    const key = crypto.createHash("md5").update(value).digest("hex");
    const cached = path.join(readelfCache, key);

    try {
        return await fs.readFile(cached, { encoding: "utf-8" });
    } catch (e) {
        const modinfo = execSync(`readelf -p .modinfo ${info.absolutePath}`, {
            encoding: "utf-8",
        }).trim();
        await fs.writeFile(cached, modinfo);
        return modinfo;
    }
}

register([".md", ".mdx"], mdxToHtml);
register([".h", ".c"], handleLanguage("c"));
register([".hpp", ".cpp"], handleLanguage("cpp"));
register([".txt"], handleLanguage("text"));
register([".zig", ".rs"], handleLanguage("rs"));
register([".yml", ".yaml"], handleLanguage("yaml"));
register([".ini", ".toml"], handleLanguage("ini"));
register([".sh"], handleLanguage("shell"));
register([".py"], handleLanguage("python"));
register([".js"], handleLanguage("js"));
register([".makefile"], handleLanguage("makefile"));
register([".dockerfile"], handleLanguage("dockerfile"));
register([".ko"], async function (info) {
    let modinfo = await cachedModInfo(info);
    return (
        <div>
            <Highlight
                lang="text"
                source={modinfo}
                filename="modinfo"
                open="true"
            ></Highlight>
        </div>
    );
});
register([".elf"], async function (info) {
    let readelf = await cachedElfInfo(info);
    // let checksec = (await $`pwn checksec ${info.sourcePath}`).stderr.trim();
    // checksec = checksec.substring(checksec.indexOf("\n") + 1);
    let checksec = "not available";

    return (
        <div>
            <Highlight
                lang="text"
                source={checksec}
                filename="checksec"
                open="true"
            ></Highlight>
            <Highlight
                lang="text"
                source={readelf}
                filename="readelf"
                open="true"
            ></Highlight>
        </div>
    );
});

const sitemap = {};
function sitemapHook(info) {
    if (info.basename.toLowerCase() == "readme") {
        sitemap[`/${info.parent.relativePath}`] = {};
    }
}

const feed = new Feed({
    title: "unvariant's blog",
    description: "pwn, assembly, low level musings",
    id: "https://unvariant.pages.dev",
    link: "https://unvariant.pages.dev",
    language: "en", // optional, used only in RSS 2.0, possible values: http://www.w3.org/TR/REC-html40/struct/dirlang.html#langcodes
    favicon: `${config.hostname}/favicon.ico`,
    // copyright: "All rights reserved 2013, John Doe",
    // updated: new Date(2013, 6, 14), // optional, default = today
    // generator: "awesome", // optional, default = 'Feed for Node.js'
    author: {
        name: config.author,
        email: config.email,
    },
});
const dates = await getCachedDates();
const blacklistedRssPaths = [path.join("random", "gallery")];
function rssHook(info, elem) {
    if (info.basename.toLowerCase() == "readme") {
        for (const item of blacklistedRssPaths) {
            if (info.relativePath.startsWith(item)) {
                return;
            }
        }

        const title = elem.props.title || `/${info.parent.relativePath}`;
        // TODO get default image here
        const image = elem.props.image || undefined;
        const authors = elem.props.authors || [
            {
                name: config.author,
                email: config.email,
            },
        ];
        const url = new URL(info.parent.relativePath, config.hostname).href;

        feed.addItem({
            title,
            link: url,
            id: url,
            description: elem.props.description,
            image,
            author: authors,
            date: dates[info.absolutePath].modified,
        });
    }
}

export class Builder {
    constructor() {
        this.rootInfo = getInfo(config.blogRoot);
        this.hooks = {
            prerender: [],
        };
    }

    registerHook(type, hook) {
        if (!this.hooks.hasOwnProperty(type)) {
            this.hooks[type] = [];
        }
        this.hooks[type].push(hook);
    }

    async renderAll() {
        await render(this.rootInfo, this.hooks);
    }
}

console.log(`[+] building ${config.blogRoot}`);
const builder = new Builder();

if (!isDevelopmentMode()) {
    builder.registerHook("preprocess", sitemapHook);
    builder.registerHook("prerender", rssHook);
}

await fs.cp("static", config.buildRoot, { recursive: true });
await builder.renderAll();
try {
    optimizer.postMessage("done");
} catch (e) {
    console.log(`postMessage failed`);
}

if (isDevelopmentMode()) {
    console.log(`skip generating sitemap in development mode`);
    console.log(`skip generating robots.txt in development mode`);
    console.log(`skip generating rss feed in development mode`);
} else {
    const links = Object.entries(sitemap).map(([url, extra]) => {
        return { url };
    });
    const stream = new SitemapStream({
        hostname: config.hostname,
    });
    let data = await streamToPromise(Readable.from(links).pipe(stream));
    await fs.writeFile(path.join(config.buildRoot, "sitemap.xml"), data);
    console.log(`done generating sitemap`);
    await fs.writeFile(
        path.join(config.buildRoot, "robots.txt"),
        `
User-agent: *
Allow: /

Sitemap: ${config.hostname}/sitemap.xml
`
    );
    console.log(`done generating robots.txt`);
    await fs.writeFile(path.join(config.buildRoot, "rss.xml"), feed.rss2());
    console.log(`done generating rss feed`);
}

console.log(`done with everything`);
