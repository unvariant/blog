import { visit } from "unist-util-visit";
import slugify from "slugify";

export default function() {
    return function(tree) {
        visit(tree, "heading", visitor);

        function visitor(node) {
            const data = node.data || (node.data = {})
            const props = data.hProperties || (data.hProperties = {});
            const slug = slugify(collect(node)).toLowerCase();

            const children = [
            {
                type: "inlineCode",
                value: "#",
                data: {
                    hProperties: {
                        id: "_hash"
                    }
                }
            },].concat(node.children);

            data.id = slug;
            props.id = slug;
            
            node.children = [{
                type: "link",
                url: `#${slug}`,
                children: children,
            }];
        }

        function collect(node) {
            if (node.hasOwnProperty("children")) {
                return node.children.map(collect).join("");
            } else if (node.hasOwnProperty("value")) {
                return node.value;
            } else {
                throw new Error("cannot determine node value");
            }
        }
    }
}