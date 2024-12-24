import * as shiki from "./shiki.js";
import * as hljs from "./hljs.js";
import fs from "node:fs";
import path from"node:path";
import config from "#utils/config.js";
import crypto from "node:crypto";

const providers = {
    shiki,
    hljs,
};
const highlightCache = path.join(config.cacheRoot, "highlight-cache");
fs.mkdirSync(highlightCache, { recursive: true });

/**
 * @param {string} provider 
 * @param {string} code 
 * @param {string} language 
 * @returns {string}
 */
export function highlight(provider, code, language) {
    if (providers.hasOwnProperty(provider)) {
        const key = crypto.createHash("md5").update(code).update(language).digest("hex");
        const cached = path.join(highlightCache, key);
    
        try {
            return fs.readFileSync(cached, { encoding: "utf-8" });
        } catch (e) {
            const html = providers[provider].highlight(code, language);
            fs.writeFileSync(cached, html);
            return html;
        }
    }

    throw Error(`unknown highlighting provider: ${provider}`);
}