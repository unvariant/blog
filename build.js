import * as path from "node:path";
import * as fs from "node:fs/promises";
import { yank } from "./yank.js";
import { getInfo } from "./src/utils/info.js";
import config from "./src/utils/config.js";

const root = getInfo(config.blogRoot);
const buildSteps = [
    yank(root),
    fs.cp("static", path.join(config.buildRoot), { recursive: true }),
];
await Promise.all(buildSteps);