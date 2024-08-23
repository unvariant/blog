export default function(props) {
    return (
        <div className={"top-bar fullWidth"}>
            <div className={"top-bar-group"}>
                <a href={"/"} className="file-link">
                    <img src={"/icons/dir.png"}></img>
                    <span>{"/"}</span>
                </a>
                <a href={".."} className="file-link">
                    <img src={"/icons/dir.png"}></img>
                    <span>{".."}</span>
                </a>
            </div>

            <div className={"top-bar-group"}>
                <h3>
                    <a href={"#_content"}>
                        <code className={"hash inline-code"}>
                            {"#"}
                        </code>
                        CONTENT
                    </a>
                </h3>
                <h3>
                    <a href={"#_top"}>
                        <code className={"hash inline-code"}>
                            {"#"}
                        </code>
                        TOP
                    </a>
                </h3>
            </div>
        </div>
    );
}