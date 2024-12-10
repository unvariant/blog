import { useInfo } from "./Context.js";
import Footer from "./Footer.mdx";
import TopBar from "./TopBar.js";
import Meta from "./Meta.js";
import Files from "./Files.js";

export default function (props) {
    const info = useInfo();

    return (
        <html id="_top">
            <head>
                <Meta></Meta>
            </head>

            <body>
                <TopBar></TopBar>

                <Files></Files>

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
