import rehypeParse from 'rehype-parse'
import rehypeStringify from 'rehype-stringify'
import { unified } from 'unified'
import { visit } from 'unist-util-visit'
import { readFileSync, writeFileSync } from 'node:fs'
import { h } from 'hastscript';

async function htmlToAst(html) {
    let ast = undefined;
    await unified()
        .use(rehypeParse, { fragment: true })
        .use(() => function (tree) {
            visit(tree, "root", function (node) {
                ast = node;
            })
        })
        .use(rehypeStringify)
        .process(html);
    return ast;
}

const file = await unified()
    .use(rehypeParse, { fragment: true })
    .use(myRehypePluginToIncreaseHeadings)
    .use(rehypeStringify)
    .process(readFileSync("testing.html"))

writeFileSync("generated.html", readFileSync("header.html") + String(file));

function myRehypePluginToIncreaseHeadings() {
    /**
     * @param {import('hast').Root} tree
     */
    return function (tree) {
        visit(tree, 'element', function (node, index, parent) {
            if (node.tagName === "pre" && node.children.length === 1 && node.children[0].tagName == "code") {
                let code = node.children[0];
                let numLines = collect(code).split("\n").length;

                // let lines = [];
                // splitByLine(code, lines);

                // for (let i = 0; i < lines.length; i++) {
                //     let line = h("div", {
                //         class: ["code-block-line-container"]
                //     }, []);

                //     line.children.push(h("div", {
                //         class: ["code-block-line-number"]
                //     }, [h("span", [`${i + 1}`])]));

                //     let wrapper = { ...node };
                //     wrapper.children = [{ ...node.children[0]}];
                //     wrapper.children[0].children = lines[i];

                //     line.children.push(h("div", {
                //         class: ["code-block-line"]
                //     }, [wrapper]));

                //     lines[i] = line;
                // }

                // const body = h("div", {
                //     class: ["code-block-body"]
                // }, lines);

                // const root = h("div", { class: ["code-block"] }, [
                //     h("div", { class: ["code-block-title"] }, [
                //         h("span", ["TITLE OR SMTH"])
                //     ]),
                //     body,
                // ]);

                const lineNumbersBox = h("pre", {
                    class: ["code-block-lines"]
                }, []);
                const maxWidth = Math.max(4, numLines.toString().length);
                const lineNumbers = Array.from(Array(numLines).keys()).map(num => `${num}`.padStart(maxWidth) + " │ ").join("\n");
                lineNumbersBox.children.push(h("span", [lineNumbers]));

                const codeBlock = h("div", {
                    class: ["code-block"]
                }, [lineNumbersBox, node]);

                parent.children[index] = codeBlock;
            }
        });

        function splitByLine(tree, results) {
            if (results.length === 0) {
                results.push([]);
            }

            tree.children.map(child => {
                if (child.type === "text") {
                    let text = child.value;
                    while (text.indexOf("\n") != -1) {
                        const idx = text.indexOf("\n");
                        results[results.length - 1].push({
                            type: "text",
                            value: text.substring(0, idx),
                        });
                        results.push([]);
                        text = text.substring(idx + 1);
                    }
                    results[results.length - 1].push({
                        type: "text",
                        value: text,
                    });
                } else if (child.type === "element" && child.tagName === "span") {
                    let text = collect(child);
                    if (text.indexOf("\n") != -1) {
                        throw new Error("cannot handle span with newlines");
                    }
                    results[results.length - 1].push(child);
                } else {
                    throw new Error("cannot process code block");
                }
            });
        }

        function collect(tree) {
            return tree.children.map(child => {
                if (child.type === "text") {
                    return child.value;
                } else {
                    return collect(child);
                }
            }).join("");
        }
    }
}