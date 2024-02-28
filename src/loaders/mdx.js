import { createLoader } from "@mdx-js/node-loader"
import rehypeHighlight from "rehype-highlight";
import { all, common } from 'lowlight';
import rehypeMdxCodeProps from 'rehype-mdx-code-props'
import remarkGfm from "remark-gfm"
import links from '../plugins/links.js';
import headers from '../plugins/headers.js';
import { languages } from '../languages.js';

export const load = await createLoader({
    providerImportSource: "@mdx-js/react",
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
                languages,
            }
        ],
        rehypeMdxCodeProps,
    ]
}).load;