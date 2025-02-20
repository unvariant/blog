import * as path from "node:path";
import * as fs from "node:fs";
import { highlight } from "../highlight.js";
import { useInfo, usePage } from "./Context.js";
import { getInfo } from "../utils/info.js";
import config from "../utils/config.js";

function count(haystack, needle) {
    return (
        haystack.length -
        haystack.replaceAll(needle, "").length +
        (haystack.endsWith(needle) ? 0 : 1)
    );
}

function collect(node) {
    if (node === undefined) {
        throw new Error("undefined node");
    } else if (typeof node === "string") {
        return node;
    } else if (typeof node === "object") {
        if (Array.isArray(node)) {
            return node.map(collect).join("");
        } else {
            if (node.props.hasOwnProperty("children")) {
                return collect(node.props.children);
            } else {
                return "";
            }
        }
    } else {
        throw new Error(
            "something went wrong collecting code text: " + typeof node
        );
    }
}

export default function (props) {
    const info = useInfo();
    const pageInfo = usePage();

    if (!Array.isArray(props.children) && props.children.type === "code") {
        let rawcode;
        let startLine;
        let endLine;
        let code = props.children;

        let lang = props.lang || "TEXT";
        if (code.props.hasOwnProperty("className")) {
            lang = /.*language\-([^\s]*)/.exec(code.props.className)[1];
        }
        lang = lang.toUpperCase();

        const filename = props.filename || props.path || "";
        const wantsHeader = !props.hasOwnProperty("noheader");
        const wantsOpen = props.hasOwnProperty("open");
        const wantsAlwaysOpen = props.hasOwnProperty("always");
        const wantsNoSticky = props.hasOwnProperty("nosticky");
        const wantsWrap = props.hasOwnProperty("wrap");
        const defaultOpen =
            (wantsHeader ? false : true) || wantsOpen || wantsAlwaysOpen;

        if (props.hasOwnProperty("path")) {
            const target = getInfo(
                path.join(path.dirname(info.absolutePath), props.path)
            );
            rawcode = target.source.toString();
            if (props.hasOwnProperty("range")) {
                const range = props.range.split(",");
                const start = parseInt(range[0], 10) || 1;
                let end = parseInt(range[1], 10) || count(rawcode, "\n");
                if (typeof range[1] === "string" && range[1].startsWith("+")) {
                    end = end + start - 1;
                }
                rawcode = rawcode
                    .split("\n")
                    .slice(start - 1, end)
                    .join("\n");
                startLine = start;
                endLine = end;
            }
        } else if (code.props.hasOwnProperty("children")) {
            rawcode = collect(code);
        } else if (code.props.hasOwnProperty("source")) {
            rawcode = code.props.source;
        } else {
            throw new Error("cannot determine code source");
        }

        const html = highlight("shiki", rawcode, lang);
        code = (
            <code
                className={code.className}
                dangerouslySetInnerHTML={{ __html: html }}
            ></code>
        );

        const maxLines = count(rawcode, "\n");
        startLine = startLine || 1;
        endLine = endLine || maxLines;

        const maxLength = Math.max(4, endLine.toString().length);
        const lines = [];
        const relativeFilePath = path.join(
            path.dirname(info.relativePath),
            filename
        );
        const linkPath = path.normalize(path.join("/", relativeFilePath, "/"));
        const linkLine = fs.existsSync(
            path.resolve(config.blogRoot, relativeFilePath)
        );

        const codeBlockId = pageInfo.codeBlockId;
        pageInfo.codeBlockId++;
        for (let i = startLine; i <= endLine; i++) {
            const num = `${i}`.padStart(maxLength) + " ";
            if (linkLine) {
                const id = `L${codeBlockId}-${i}`;
                const line = linkPath + `#${id}`;
                lines.push(
                    /* target="_blank" rel="noopener" */
                    <a key={id} id={id} href={line}>
                        {num}
                        <div className="highlight">
                            <pre> </pre>
                        </div>
                    </a>
                );
                lines.push("\n");
            } else {
                lines.push(num + "\n");
            }
        }

        const wrapping = wantsWrap
            ? "code-block-code-wrap"
            : "code-block-code-nowrap";
        let codeBlock = (
            <div className="code-block">
                <div className="code-block-lines">
                    <pre>{lines}</pre>
                </div>
                <div className={`code-block-code ${wrapping}`}>
                    <pre>{code}</pre>
                </div>
            </div>
        );

        let displayName = <b>{filename}</b>;

        let className = wantsAlwaysOpen ? "always-open" : "";
        className = `${className} codeblock`;

        if (wantsHeader) {
            codeBlock = (
                <details open={defaultOpen} className={className}>
                    <summary className={`${wantsNoSticky ? "" : "sticky"}`}>
                        {displayName}
                        <b>{lang}</b>
                    </summary>
                    {codeBlock}
                </details>
            );
        }

        return codeBlock;
    }

    throw Error("what to do");
}
