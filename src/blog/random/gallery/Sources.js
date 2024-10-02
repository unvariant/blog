export default function (props) {
    let sourceLinks = <p>Oops! something went wrong.</p>;
    if (Array.isArray(props.links)) {
        sourceLinks = props.links.map((link) => (
            <li>
                <a
                    href={link}
                    target="_blank"
                    rel="noopener noreferrer"
                    class="ellipsis"
                >
                    {link}
                </a>
            </li>
        ));
    } else {
        sourceLinks = Object.entries(props.links)
            .map(([label, link]) => {
                if (link !== undefined) {
                    return (
                        <a
                            href={link}
                            target="_blank"
                            rel="noopener noreferrer"
                            class="ellipsis"
                        >
                            {label}
                        </a>
                    );
                } else {
                    return <span>{label}</span>;
                }
            })
            .map((e) => <li>{e}</li>);
    }

    return (
        <div>
            <details class="sources fullwidth">
                <summary class="fullwidth">
                    <h3>Sources (Click me!)</h3>
                </summary>
                <div class="links fullwidth">
                    <ul>{sourceLinks}</ul>
                </div>
            </details>
        </div>
    );
}
