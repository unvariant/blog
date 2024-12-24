import CodeBlock from './CodeBlock.js';

export default function ({ lang, ...props }) {
    let source;
    let filename;

    if (props.info !== undefined) {
        source = props.info.source.toString();
        filename = props.info.filename;
    } else if (props.source !== undefined) {
        source = props.source;
        filename = props.filename || "";
    } else {
        throw new Error("unable to determine what to highlight");
    }

    lang = lang || "TEXT";

    return (
        <CodeBlock { ...props } lang={ lang } filename={ filename }>
            <code source={ source }>
            </code>
        </CodeBlock>
    );
}