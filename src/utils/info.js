import * as path from "node:path";
import * as fs from "node:fs/promises";
import { lstatSync, readFileSync } from "node:fs";
import { execSync } from "node:child_process";
import config from "./config.js";

const infoMemo = new Map();

/**
 * @param {string} absolutePath 
 * @returns {Info}
 */
export function getInfo(absolutePath, useCached = true) {
    absolutePath = path.resolve(absolutePath);
    if (infoMemo.has(absolutePath) && useCached) {
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
        const relativePath = path.relative(config.blogRoot, absolutePath);
        const extname = path.extname(absolutePath);
        const basename = path.basename(absolutePath, extname);
        const filename = path.basename(absolutePath);
        const stats = lstatSync(absolutePath);
        let lastModifiedDate = new Date(0);
        if (relativePath.startsWith("..")) {
            lastModifiedDate = new Date(0);
        } else {
            lastModifiedDate = new Date(execSync(`git log -1 --pretty="format:%cD" ${absolutePath}`, { encoding: "utf-8" }));
            if (isNaN(lastModifiedDate)) {
                lastModifiedDate = new Date(0);
            }
        }

        this.resolved = 0;
        this.pushChildren = true;
        this.absolutePath = absolutePath;
        this.relativePath = relativePath;
        this.stats = stats;
        this.extname = extname;
        this.basename = basename;
        this.filename = filename;
        this.lastModifiedDate = lastModifiedDate;
        this.element = (<></>);
        if (infoMemo.has(absolutePath)) {
            this.reloadCount = infoMemo.get(absolutePath).reloadCount + 1;
        } else {
            this.reloadCount = 0;
        }
        if (stats.isFile()) {
            this.size = stats.size;
        } else {
            this.size = 0;
        }

        Object.defineProperty(this, "parent", {
            get: function() {
                const resolvedParent = (absolutePath === config.cwd) ? undefined : getInfo(path.resolve(absolutePath, ".."));

                Object.defineProperty(this, "parent", {
                    value: resolvedParent,
                    writable: false,
                    configurable: false
                });

                return resolvedParent;
            },
            configurable: true,
            enumerable: true
        });

        Object.defineProperty(this, "source", {
            get: function() {
                const resolvedSource = readFileSync(this.absolutePath);

                Object.defineProperty(this, "source", {
                    value: resolvedSource,
                    writable: false,
                    configurable: false
                });

                return resolvedSource;
            },
            configurable: true,
            enumerable: true
        });

        Object.defineProperty(this, "children", {
            get: function() {
                let resolvedChilren = [];
                if (this.stats.isDirectory()) {
                    const files = execSync(`fd -d 1 --hidden . '${this.absolutePath}'`, { encoding: "utf-8" }).trim().split("\n").filter(s => s.length > 0);
                    resolvedChilren = files.map(file => getInfo(file));
                }

                Object.defineProperty(this, "children", {
                    value: resolvedChilren,
                    writable: false,
                    configurable: false
                });

                return resolvedChilren;
            },
            configurable: true,
            enumerable: true
        });

        // Object.defineProperty(this, "size", {
        //     get: function() {
        //         let resolvedSize = this.stats.size;
        //         if (this.stats.isDirectory()) {
        //             resolvedSize = this.children.map(i => i.size).concat([0, 0]).reduce((a, b) => a + b);
        //         }

        //         Object.defineProperty(this, "size", {
        //             value: resolvedSize,
        //             writable: false,
        //             configurable: false
        //         });

        //         return resolvedSize;
        //     },
        //     configurable: true,
        //     enumerable: true
        // });
    }
}