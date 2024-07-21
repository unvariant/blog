import Footer from "./Footer.mdx";
import FileEntry from "./FileEntry.js";
import { useInfo } from "./InfoContext.js";

export default function (props) {
    const info = useInfo();

    return (
        <html id="_top">
            <head>
                <meta
                    name="viewport"
                    content="width=device-width, initial-scale=1"
                ></meta>

                {props.children.props.title ? (
                    <title>{props.children.props.title}</title>
                ) : (
                    <></>
                )}
                {/* <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github.min.css"></link> */}

                <link rel="stylesheet" href="/style.css"></link>
                {/* <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
                <script>hljs.highlightAll();</script> */}
            </head>

            <body>
                <div className={"top-bar fullWidth"}>
                    <div className={"top-bar-group"}>
                        <a href={"/"} className="file-link">
                            <img src={"/icons/dir.png"}></img>
                            <span>{"/"}</span>
                        </a>
                        <a href={".."} className="file-link">
                            <img src={"/icons/dir.png"}></img>
                            <span>{".."}</span>
                        </a>
                    </div>

                    <div className={"top-bar-group"}>
                        <h3>
                            <a href={"#_content"}>
                                <code className={"hash inline-code"}>
                                    {"#"}
                                </code>
                                CONTENT
                            </a>
                        </h3>
                        <h3>
                            <a href={"#_top"}>
                                <code className={"hash inline-code"}>
                                    {"#"}
                                </code>
                                TOP
                            </a>
                        </h3>
                    </div>
                </div>
                {
                    [
                        // FileEntry(info, {
                        //     filename: "."
                        // }),
                        // FileEntry(info.parent, {
                        //     filename: "..",
                        // }),
                    ]
                }

                {props.children}

                <Footer />
            </body>
        </html>
    );
}
