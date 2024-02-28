export default {
    pre: function (props) {
        if (!Array.isArray(props.children) && props.children.type === "code") {
            function count(haystack, needle) {
                return haystack.split("").map(ch => ch == needle ? 1 : 0).reduce((a, b) => a + b);
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
                }
            }

            const code = props.children;
            const numLines = count(collect(code), "\n");
            const maxLength = Math.max(4, numLines.toString().length);
            const lines = Array.from(Array(numLines).keys()).map(i => `${i + 1}`.padStart(maxLength)).map(num => `${num} `).join("\n");

            const lang = /.*language\-([^\s]*)/.exec(code.props.className)[1].toUpperCase();
            const filename = props.filename || "";
            const wantsHeader = !props.hasOwnProperty("noheader");
            const wantsOpen = props.hasOwnProperty("open");
            const defaultOpen = (wantsHeader ? false : true) || wantsOpen;

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
                    <details open={defaultOpen}>
                        <summary className="code-block-summary">
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
};