import { visit } from "unist-util-visit";

export default function() {
    return function(tree) {
        visit(tree, "link", visitor);

        function visitor(node) {
            const data = node.data || (node.data = {});
            const props = data.hProperties || (data.hProperties = {});
            const url = node.url;

            function getLinkType(url) {
                // any string that starts with #
                if (/^#(.*)/.exec(url)) {
                    return "hash";
                // any string that starts with /
                } else if (/^\/(.*)/.exec(url)) {
                    return "relative";
                // any string with ://
                } else if (url.indexOf("://") == -1) {
                    return "relative";
                } else {
                    return "external";
                }
            };

            const linkType = getLinkType(url);

            props.title = node.url;

            if (linkType === "external") {
                props.target = "_blank";
                props.rel = "noopener";
            }
        }
    }
}