import * as path from "node:path";
import { execSync } from "node:child_process";

const cwd = path.resolve("");
const blogRoot = path.resolve(cwd, "src/blog");
const buildRoot = path.resolve(cwd, "build");

export default {
    cwd,
    blogRoot,
    buildRoot,
};