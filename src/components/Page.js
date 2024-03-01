import Footer from './Footer.mdx';
import FileEntry from "./FileEntry.js";
import { useInfo } from "./InfoContext.js";

export default function(props) {
    const info = useInfo();

    return (
        <html>
            <head>
                <meta name="viewport" content="width=device-width, initial-scale=1"></meta>

                { props.children.props.title ? <title>{ props.children.props.title }</title> : <></> }
                {/* <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github.min.css"></link> */}

                <link rel="stylesheet" href="/style.css"></link>
                {/* <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
                <script>hljs.highlightAll();</script> */}

                <link rel="preconnect" href="https://fonts.googleapis.com"/>
                <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="true"/>
                {/* <link href="https://fonts.googleapis.com/css2?family=Inter:wght@100..900&display=swap" rel="stylesheet"/> */}
                <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:ital,wght@0,100..800;1,100..800&display=swap" rel="stylesheet"/>
            </head>

            <body>
                { [
                    FileEntry(info, {
                        filename: "."
                    }),
                    FileEntry(info.parent, {
                        filename: ".."
                    }),
                ] }

                { props.children }

                <Footer />
            </body>
        </html>
    );
}