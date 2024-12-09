export function Friend(props) {
    return (
        <div
            style={{
                display: "flex",
                flexDirection: "column",
            }}
        >
            <h2
                style={{
                    borderBottom: "2px solid black",
                    marginBottom: "0px",
                }}
            >
                {props.name}
            </h2>
            <div
                style={{
                    display: "flex",
                    flexDirection: "row",
                }}
            >
                <img
                    style={{
                        padding: "10px",
                    }}
                    src="/favicon.ico"
                ></img>
                <p style={{}}>{props.description}</p>
            </div>
        </div>
    );
}
