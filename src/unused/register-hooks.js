import { register } from 'node:module';

const parentURL = import.meta.url;

register("import-jsx", parentURL);
register("./src/loaders/mdx.js", parentURL);