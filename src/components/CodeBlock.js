import * as path from "node:path";
import * as fs from "node:fs";
import hljs from "../languages.js";
import { useInfo } from "./InfoContext.js";

export default function (props) {
    const info = useInfo();

    if (!Array.isArray(props.children) && props.children.type === "code") {
        function count(haystack, needle) {
            return haystack.split("").map(ch => ch == needle ? 1 : 0).concat([0, 0]).reduce((a, b) => a + b);
        }

        function collect(node) {
            if (typeof node === "string") {
                return node;
            } else if (typeof node === "object") {
                if (Array.isArray(node)) {
                    return node.map(collect).join("");
                } else {
                    return collect(node.props.children);
                }
            } else {
                throw new Error("something went wrong collecting code text");
            }
        }

        let rawcode;
        let code = props.children;

        const lang = /.*language\-([^\s]*)/.exec(code.props.className)[1].toUpperCase();
        const filename = props.filename || props.path || "";
        const wantsHeader = !props.hasOwnProperty("noheader");
        const wantsOpen = props.hasOwnProperty("open");
        const wantsAlwaysOpen = props.hasOwnProperty("always");
        const defaultOpen = (wantsHeader ? false : true) || wantsOpen || wantsAlwaysOpen;

        if (props.hasOwnProperty("path")) {
            const filepath = path.join(path.dirname(info.absolutePath), props.path);
            rawcode = fs.readFileSync(filepath).toString();
            const html = hljs.highlight(rawcode, { language: lang }).value;
            code = (
                <code className={ code.className } dangerouslySetInnerHTML={{ __html: html }}>
                </code>
            );
        } else if (code.props.hasOwnProperty("children")) {
            rawcode = collect(code);
        } else if (code.props.hasOwnProperty("dangerouslySetInnerHTML")) {
            rawcode = code.props.dangerouslySetInnerHTML.__html;
        } else {
            rawcode = "";
        }

        const numLines = count(rawcode, "\n") + (rawcode.endsWith("\n") ? 0 : 1);
        const maxLength = Math.max(4, numLines.toString().length);
        const lines = Array.from(Array(numLines).keys()).map(i => `${i + 1}`.padStart(maxLength)).map(num => `${num} `).join("\n");

        let codeBlock = (
            <div className="code-block">
                <div className="code-block-lines">
                    <pre>
                        {lines}
                    </pre>
                </div>
                <div className="code-block-code">
                    <pre>
                        {code}
                    </pre>
                </div>
            </div>
        );

        if (wantsHeader) {
            codeBlock = (
                <details open={defaultOpen} className={ `${ wantsAlwaysOpen ? "always-open" : "" }` }>
                    <summary>
                        <div>
                            <b>{filename}</b>
                        </div>
                        <div>
                            <b>{lang}</b>
                        </div>
                    </summary>
                    {codeBlock}
                </details>
            );
        }

        return codeBlock;
    }
    return props;
}