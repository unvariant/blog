export default function(props) {
    return (
        <>
                <meta
                    name="viewport"
                    content="width=device-width, initial-scale=1"
                ></meta>

                {/* im lazy deal with title later */}
                {/* {props.children.props.title ? (
                    <title>{props.children.props.title}</title>
                ) : (
                    <></>
                )} */}

                <link rel="stylesheet" href="/fonts.css" type="text/css" preload></link>
                <link rel="stylesheet" href="/style.css" type="text/css" preload></link>
        </>
    );
}
