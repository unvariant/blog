export function ChallengeInfo (props) {
    let table = [];
    let maxWidth = 0;
    const temp = props.items || {};
    const items = {
        author: temp.author || "unvariant",
        category: temp.category || "pwn",
        points: temp.points || "unknown",
        solves: temp.solves || "unknown",
        ...temp,
    };

    for (const key of Object.keys(items)) {
        maxWidth = Math.max(maxWidth, key.length);
    }

    for (let [key, val] of Object.entries(items)) {
        const padding = "&nbsp;".repeat(maxWidth - key.length);
        table.push(
            <span key={key} className={"challenge-info-item"}>
                <span className={"challenge-info-item-val"}>{val}</span>
                {" <- "}
                <span dangerouslySetInnerHTML={{ __html: padding }}></span>
                <span className={"challenge-info-item-key"}>{key} </span>
            </span>
        );
    }

    return (
        <div className="fullwidth challenge-info">
            <div
                className="fullwidth"
                style={{
                    display: "flex",
                    flexDirection: "row",
                    justifyContent: "space-between",
                }}
            >
                <div>
                    <div>{props.children}</div>
                </div>
                <div
                    style={{
                        display: "flex",
                        flexDirection: "column",
                        textAlign: "right",
                    }}
                >
                    {table}
                </div>
            </div>
        </div>
    );
}
