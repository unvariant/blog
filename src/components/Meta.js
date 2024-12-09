import { useInfo, usePage } from "./Context.js";

export default function(props) {
    const info = useInfo();
    const page = usePage();

    const description = page.description ? (<meta name="description" content={ page.description }></meta>) : (<></>);

    return (
        <>
                <meta charset="UTF-8"></meta>
                <meta
                    name="viewport"
                    content="width=device-width, initial-scale=1"
                ></meta>
                <title>{ "/" + info.relativePath }</title>
                <meta name="author" content="unvariant"></meta>
                { description }

                <link rel="stylesheet" href="/fonts.css" type="text/css" preload></link>
                <link rel="stylesheet" href="/style.css" type="text/css" preload></link>
        </>
    );
}
