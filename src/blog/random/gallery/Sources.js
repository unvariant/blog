export default function(props) {
    const sourceLinks = props.links.map(link => (
        <li>
            <a href={ link } target="_blank" rel="noopener noreferrer" class="ellipsis">{ link }</a>
        </li>
    ));
    return (
        <div>
            <details class="sources fullwidth">
                <summary class="fullwidth">
                    <h3>Sources (Click me!)</h3>
                </summary>
                <div class="links fullwidth">
                    <ul>
                        { sourceLinks }
                    </ul>
                </div>
            </details>
        </div>
    );
}