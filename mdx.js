import { createLoader } from "@mdx-js/node-loader"
import rehypeHighlight from "rehype-highlight";
import { all, common } from 'lowlight';
import rehypeMdxCodeProps from 'rehype-mdx-code-props'
import remarkGfm from "remark-gfm"
import links from './plugins/links.js';
import headers from './plugins/headers.js';

export const load = await createLoader({
    remarkPlugins: [
        remarkGfm,
        links,
        headers,
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
        [
            rehypeHighlight, {
                languages: {
                    // mipsasm, avrasm
                    armasm: all["armasm"],
                    x86asm: all["x86asm"],
                    c: all["c"],
                    python: all["python"],
                    rust: all["rust"],
                    shell: all["shell"],
                    plaintext: all["plaintext"],
                    makefile: all["makefile"],
                    json: all["json"],
                    diff: all["diff"],
                    bash: all["bash"],
                    dockerfile: all["dockerfile"],
                    cpp: all["cpp"],
                }
            }
        ],
        rehypeMdxCodeProps,
    ]
}).load;