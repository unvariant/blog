export default function(props) {
    const altText = props.alt || "";
    return (
        <img src={ props.src } alt={ altText } style={{
            maxWidth: "100%",
            maxHeight: "100%",
        }}></img>
    );
}