import Footer from "./Footer.mdx";
import FileEntry from "./FileEntry.js";
import TopBar from "./TopBar.js";
import Meta from "./Meta.js";
import { useInfo } from "./InfoContext.js";

export default function (props) {
    const info = useInfo();

    return (
        <html id="_top">
            <head>
                <Meta></Meta>
            </head>

            <body>
                <TopBar></TopBar>
                
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
