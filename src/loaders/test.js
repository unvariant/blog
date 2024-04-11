import path from "node:path";
import fs from "node:fs/promises";
import os from "node:os"
import swc from "@swc/core";
import crypto from 'node:crypto';

const cacheDirectory = os.tmpdir();

const cacheKeyFromSource = source => {
	return crypto.createHash('md5').update(source).digest('hex') + '.js';
};

export async function load(url, _context, nextLoad) {
    if (!url.endsWith('.js') || url.includes('node_modules')) {
        return nextLoad(url);
    }

    const result = await nextLoad(url);

    if (!result.source) {
        return result;
    }

    const source = result.source.toString();
    const key = cacheKeyFromSource(source);
    const cached = path.join(cacheDirectory, key);

    try {
        return {
            source: await fs.readFile(cached),
            format: 'module',
            shortCircuit: true,
        };
    } catch {}

    const transformed = await swc.transform(source, {
        filename: url,
        sourceMaps: false,
        jsc: {
            parser: {
                jsx: true,
            },
            transform: {
                react: {
                    runtime: "automatic"
                }
            }
        }
    });

    await fs.writeFile(cached, transformed.code);

    return {
        source: transformed.code,
        format: 'module',
        shortCircuit: true
    };
}