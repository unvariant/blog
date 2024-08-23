export default function(props) {
    const overrides = props.style || {};
    const className = props.className || "";

    return (
        <div style={{
            display: "flex",
            flexDirection: "row",
            ...overrides
        }} className={ `fullwidth ${className}` }>
            { props.children }
        </div>
    );
}