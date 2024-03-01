import CodeBlock from './CodeBlock.js';
import * as fs from 'node:fs';
import hljs from '../languages.js';

export default function ({ lang, ...props }) {
    let source;
    let filename;

    if (props.info) {
        source = props.info.source.toString();
        filename = props.info.filename;
    } else if (props.source) {
        source = props.source;
        filename = props.filename || "";
    } else {
        throw new Error("unable to determine what to highlight");
    }

    let html;
    if (hljs.getLanguage(lang)) {
        html = hljs.highlight(source, { language: lang }).value;
    } else {
        html = source;
        lang = "text";
    }

    return (
        <CodeBlock { ...props } lang={ lang } filename={ filename }>
            <code className={ `hljs language-${lang}` } dangerouslySetInnerHTML={{ __html: html }}>
            </code>
        </CodeBlock>
    );
}