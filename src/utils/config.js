import * as path from "node:path";
import { execSync } from "node:child_process";

const cwd = path.resolve("");
const blogRoot = path.resolve(cwd, "src/blog");
const buildRoot = path.resolve(cwd, "build");
const files = execSync(`fd --hidden . '${blogRoot}'`, { encoding: "utf-8" })
    .trim()
    .split("\n")
    .filter((s) => s.length > 0)
    .map((file) => path.parse(file));

export default {
    cwd,
    blogRoot,
    buildRoot,
    files,
};
