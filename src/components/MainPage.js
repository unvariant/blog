import Footer from "./Footer.mdx";
import TopBar from "./TopBar.js";
import Meta from "./Meta.js";
import Files from "./Files.js";
import config, { dates, posts } from "#utils/config.js";
import { getInfo } from "#utils/info.js";

export default function (props) {
    const recentByDate = posts
        .filter((p) => dates.hasOwnProperty(p))
        .map((p) => [getInfo(p), dates[p].created])
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
        .slice(0, 4);
    const recentPostsList = recentByDate.map(([info, date]) => {
        return (
            <p>
                {date.toDateString()}
                <br></br>
                <a
                    href={`${config.hostname}/${info.relativePath}`}
                >{`${info.filename}`}</a>
            </p>
        );
    });

    const recent = recentByDate.length > 0 ? recentByDate[0][0] : undefined;
    const recentPost = recent ? (
        <div>
            <h1>{recent.readme.props.title}</h1>
            {recent.element}
        </div>
    ) : (
        <></>
    );

    return (
        <html id="_top">
            <head>
                <Meta></Meta>
            </head>

            <body>
                <TopBar></TopBar>

                <Files></Files>

                <div className="fullwidth side-bar">
                    <div
                        id="_content"
                        className="blogwidth"
                        style={{
                            scrollMarginTop: "48px",
                            overflow: "hidden",
                            overflowWrap: "break-word",
                        }}
                    >
                        {props.children}
                    </div>
                    <div id="posts">
                        <h4>recent posts</h4>
                        {recentPostsList}
                        <p>
                            <a href="/all-posts.mdx/">- all posts -</a>
                        </p>
                    </div>
                </div>

                {recentPost}

                <Footer />
            </body>
        </html>
    );
}
