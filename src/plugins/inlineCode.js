import { visit } from "unist-util-visit";

export default function() {
    return function(tree) {
        visit(tree, "inlineCode", visitor);

        function visitor(node) {
            const data = node.data || (node.data = {});
            const props = data.hProperties || (data.hProperties = {});
            props.className = props.className || [];
            props.className.push("inline-code");
        }
    }
}