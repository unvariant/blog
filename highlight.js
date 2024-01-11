import hljs from 'highlight.js';
import { toText } from 'hast-util-to-text'
import { visit } from 'unist-util-visit'

export default function custom(options) {
    return function (tree, file) {
        visit(tree, "element", function (node, _, parent) {
            if (
                node.tagName !== "code" ||
                !parent ||
                parent.type !== "element" ||
                parent.tagName !== "pre"
            ) {
                return;
            }

            const lang = language(node);

            if (!Array.isArray(node.properties.className)) {
                node.properties.className = [];
            }

            let result;

            try {
                result = lang
                    ? hljs.highlight(toText(parent), { language: lang })
                    : hljs.highlightAuto(toText(parent))
            } catch (error) {
                throw error;
            }

            console.log(result);

            node.children = result;
        });
    };
}

function language(node) {
    const list = node.properties.className
    let index = -1

    if (!Array.isArray(list)) {
        return
    }

    let name

    while (++index < list.length) {
        const value = String(list[index])

        if (value === 'no-highlight' || value === 'nohighlight') {
            return false
        }

        if (!name && value.slice(0, 5) === 'lang-') {
            name = value.slice(5)
        }

        if (!name && value.slice(0, 9) === 'language-') {
            name = value.slice(9)
        }
    }

    return name
}
