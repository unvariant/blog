import Footer from "./Footer.mdx";
import FileEntry from "./FileEntry.js";
import TopBar from "./TopBar.js";
import Meta from "./Meta.js";
import { useInfo } from "./Context.js";

export default function (props) {
    const info = useInfo();

    return (
        <html id="_top">
            <head>
                <Meta></Meta>
            </head>

            <body>
                <TopBar></TopBar>

                { info.children
                    .filter(info => info.stats.isDirectory())
                    .sort((a, b) => a.filename.localeCompare(b.filename))
                    .map(FileEntry)
                }
                { info.children
                    .filter(info => info.stats.isFile() || info.stats.isSymbolicLink())
                    .sort((a, b) => a.filename.localeCompare(b.filename))
                    .map(FileEntry)
                }

                <div id="_content" style={{
                    scrollMarginTop: "48px",
                }}>
                    { props.children }
                </div>

                <Footer />
            </body>
        </html>
    );
}
