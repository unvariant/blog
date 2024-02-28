import * as path from "node:path";
import * as fs from "node:fs";

export async function load(url, context, next) {
    const extname = path.extname(url);
    const filename = path.basename(url);
    const basename = path.basename(url, extname);

    if (extname == ".c") {
        return {
            raw: await fs.readFile(url),
        };
    }

	return next(url, context);
}