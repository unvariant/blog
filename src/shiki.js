import { createHighlighterCoreSync } from "shiki/core";
import { createOnigurumaEngine } from "shiki/engine/oniguruma";
import c from "shiki/langs/c.mjs";
import cpp from "shiki/langs/cpp.mjs";
import rs from "shiki/langs/rs.mjs";
import makefile from "shiki/langs/makefile.mjs";
import asm from "shiki/langs/asm.mjs";
import shell from "shiki/langs/shell.mjs";
import bash from "shiki/langs/bash.mjs";
import python from "shiki/langs/python.mjs";
import diff from "shiki/langs/diff.mjs";
import dockerfile from "shiki/langs/dockerfile.mjs";
import html from "shiki/langs/html.mjs";
import json from "shiki/langs/json.mjs";
import yaml from "shiki/langs/yaml.mjs";
import ini from "shiki/langs/ini.mjs";
import toml from "shiki/langs/toml.mjs";
import js from "shiki/langs/javascript.mjs";
import zig from "shiki/langs/zig.mjs";
import { highlight as hljs } from "./hljs.js";

import theme from "shiki/themes/github-light.mjs";
import { transformerColorizedBrackets } from "@shikijs/colorized-brackets";

const languages = {
    c,
    cpp,
    rs,
    makefile,
    asm,
    shell,
    bash,
    python,
    diff,
    dockerfile,
    html,
    json,
    yaml,
    ini,
    toml,
    js,
    zig,
};
const overrides = Object.entries({
    asm: ["armasm", "x86asm", "mipsasm"],
    python: ["py"],
    js: ["javascript"],
})
    .map(([lang, aliases]) => aliases.map((alias) => [alias, lang]))
    .flat();
const mapping = Object.fromEntries(
    Object.keys(languages)
        .map((lang) => [lang, lang])
        .concat(overrides)
);
mapping["ansi"] = "ansi";

// Load this somewhere beforehand
const engine = await createOnigurumaEngine(import("shiki/wasm"));
const langs = Object.values(languages);

const shiki = createHighlighterCoreSync({
    themes: [theme],
    langs,
    engine, // if a resolved engine passed in, the rest can still be synced.
});

/**
 *
 * @param {string} code
 * @param {string} language
 * @returns {string}
 */
export function highlight(code, language) {
    const lines = code.split("\n").length;
    // shiki is really bad with big files
    if (lines > 1000) {
        return hljs(code, language);
    }
    const lang = language.toLowerCase();
    if (mapping.hasOwnProperty(lang)) {
        // console.log(lang);
        return shiki.codeToHtml(code, {
            lang: mapping[lang],
            theme: "github-light",
            transformers: [transformerColorizedBrackets()],
            structure: "inline",
        });
    }

    return code;
}
