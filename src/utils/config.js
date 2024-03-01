import * as path from "node:path";

const cwd = path.resolve("");
const blogRoot = path.resolve(cwd, "src/blog");
const buildRoot = path.resolve(cwd, "build");

export default {
    cwd,
    blogRoot,
    buildRoot,
};