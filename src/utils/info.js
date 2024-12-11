import path from "node:path";
import fs from "node:fs/promises";
import { lstatSync, readFileSync } from "node:fs";
import { execSync } from "node:child_process";
import config, { dates } from "./config.js";

export const infoMemo = new Map();

/**
 * @param {string} absolutePath
 * @returns {Info}
 */
export function getInfo(absolutePath) {
    absolutePath = path.resolve(absolutePath);
    if (infoMemo.has(absolutePath)) {
        return infoMemo.get(absolutePath);
    } else {
        const info = new Info(absolutePath);
        infoMemo.set(absolutePath, info);
        return info;
    }
}

export function removeInfo(absolutePath) {
    absolutePath = path.resolve(absolutePath);
    if (infoMemo.has(absolutePath)) {
        infoMemo.delete(absolutePath);
    }
}

class Info {
    /**
     * @param {string} absolutePath
     */
    constructor(absolutePath) {
        if (typeof absolutePath !== "string") {
            console.warn(`${absolutePath} is not a string`);
        }

        const relativePath = path.relative(config.blogRoot, absolutePath);
        const extname = path.extname(absolutePath);
        const basename = path.basename(absolutePath, extname);
        const filename = path.basename(absolutePath);
        const dirname = path.dirname(absolutePath);
        const stats = lstatSync(absolutePath);
        let lastModifiedDate = undefined;
        if (relativePath.startsWith("..")) {
            lastModifiedDate = new Date(-1);
        } else {
            lastModifiedDate = new Date(dates[absolutePath].modified);
        }

        this.absolutePath = absolutePath;
        this.relativePath = relativePath;
        this.stats = stats;
        this.extname = extname;
        this.basename = basename;
        this.filename = filename;
        this.dirname = dirname;
        this.lastModifiedDate = lastModifiedDate;
        this.element = undefined;
        if (stats.isFile()) {
            this.size = stats.size;
        } else {
            this.size = 0;
        }
        if (this.stats.isDirectory()) {
            this.children = config.files
                .filter((parsedPath) => parsedPath.dir === absolutePath)
                .map((parsedPath) => path.join(parsedPath.dir, parsedPath.base))
                .map(getInfo);
        } else {
            this.children = [];
        }

        Object.defineProperty(this, "parent", {
            get: function () {
                const resolvedParent =
                    absolutePath === config.cwd
                        ? undefined
                        : getInfo(path.join(absolutePath, ".."));

                Object.defineProperty(this, "parent", {
                    value: resolvedParent,
                    writable: false,
                    configurable: false,
                });

                return resolvedParent;
            },
            configurable: true,
            enumerable: true,
        });

        Object.defineProperty(this, "source", {
            get: function () {
                const resolvedSource = readFileSync(this.absolutePath);

                Object.defineProperty(this, "source", {
                    value: resolvedSource,
                    writable: false,
                    configurable: false,
                });

                return resolvedSource;
            },
            configurable: true,
            enumerable: true,
        });
    }
}
