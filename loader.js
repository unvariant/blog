import { createLoader } from "@mdx-js/node-loader"
import highlighter from './highlight.js';

export const load = await createLoader({
    // rehypePlugins: [highlighter]
}).load;