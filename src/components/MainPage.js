import Footer from "./Footer.mdx";
import TopBar from "./TopBar.js";
import Meta from "./Meta.js";
import Files from "./Files.js";
import config, { dates } from "#utils/config.js";
import { getInfo } from "#utils/info.js";

export default function (props) {
    const postWhitelist = ["writeups", "notes"];
    const recent = Object.entries(dates)
        .map(([p, date]) => [getInfo(p), date.created])
        .filter(
            ([info, date]) =>
                info.basename.toLowerCase() == "readme" &&
                postWhitelist.find((entry) =>
                    info.parent.relativePath.startsWith(entry)
                ) &&
                info.stats.isFile()
        )
        .sort(([i1, a], [i2, b]) => {
            // reverse sort
            if (a == b) {
                return 0;
            } else if (a > b) {
                return -1;
            } else if (a < b) {
                return 1;
            }
        })
        .slice(0, 5)
        .map(([info, date]) => {
            return (
                <p>
                    {date.toDateString()}
                    <br></br>
                    <a
                        href={`${config.hostname}/${info.parent.relativePath}`}
                    >{`${info.parent.filename}`}</a>
                </p>
            );
        });

    return (
        <html id="_top">
            <head>
                <Meta></Meta>
            </head>

            <body>
                <TopBar></TopBar>

                <Files></Files>

                <div
                    className="fullwidth"
                    style={{
                        display: "flex",
                        flexDirection: "row",
                    }}
                >
                    <div
                        id="_content"
                        className="blogwidth"
                        style={{
                            scrollMarginTop: "48px",
                        }}
                    >
                        {props.children}
                    </div>
                    <div>
                        <h4>recent posts</h4>
                        {recent}
                    </div>
                </div>

                <Footer />
            </body>
        </html>
    );
}