import rehypeHighlight from "rehype-highlight";
import rehypeMdxCodeProps from "rehype-mdx-code-props";
import remarkGfm from "remark-gfm";
import links from "../plugins/links.js";
import headers from "../plugins/headers.js";
import inlineCode from "../plugins/inlineCode.js";
import { languages } from "../highlight.js";
import { createFormatAwareProcessors } from "@mdx-js/mdx/internal-create-format-aware-processors";
import { extnamesToRegex } from "@mdx-js/mdx/internal-extnames-to-regex";
import { VFile } from "vfile";
import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import hash from "object-hash";

const options = {
    development: true,
    providerImportSource: "@mdx-js/preact",
    remarkPlugins: [
        remarkGfm,
        links,
        headers,
        inlineCode,
        // remarkFrontmatter,
        // remarkMdxFrontmatter,
        // [
        //     remarkFrontMatter,
        //     {
        //         type: 'yaml',
        //         marker: '-',
        //     }
        // ]
    ],
    rehypePlugins: [
        // [
        //     rehypeHighlight,
        //     {
        //         languages,
        //     },
        // ],
        rehypeMdxCodeProps,
    ],
};

const cacheRoot = path.join(path.resolve("."), "_cache");
const projectHash = `mdx-cache-${hash(options)}`;
const cache = path.join(cacheRoot, projectHash);
await fs.mkdir(cache, { recursive: true });

const { extnames, process } = createFormatAwareProcessors(options);
const regex = extnamesToRegex(extnames);

export async function load(href, context, nextLoad) {
    const url = new URL(href);

    if (url.protocol === "file:" && regex.test(url.pathname)) {
        const value = await fs.readFile(url);

        const key = crypto.createHash("md5").update(value).digest("hex");
        const cached = path.join(cache, key);
        let source;

        try {
            source = await fs.readFile(cached, { encoding: "utf-8" });
        } catch (e) {
            const file = await process(new VFile({ value, path: url }));
            source = String(file);
            await fs.writeFile(cached, source);
        }

        return { format: "module", shortCircuit: true, source };
    }

    return nextLoad(href, context);
}
