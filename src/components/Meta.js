import { useInfo } from "./InfoContext.js";

export default function(props) {
    const info = useInfo();

    return (
        <>
                <meta
                    name="viewport"
                    content="width=device-width, initial-scale=1"
                ></meta>
                <title>{ "/" + info.relativePath }</title>

                <link rel="stylesheet" href="/fonts.css" type="text/css" preload></link>
                <link rel="stylesheet" href="/style.css" type="text/css" preload></link>
        </>
    );
}
