import { readFileSync } from "fs";
import { useInfo } from "../../../components/InfoContext.js";

export default function(props) {
    const info = useInfo();
    const altText = props.alt || "";
    const bytes = readFileSync(`${info.dirname}/${props.src}`);
    const base64 = bytes.toString('base64');
    const image = `data:image/jpeg;charset=utf-8;base64,${base64}`;

    return (
        <img src={ image } alt={ altText } style={{
            maxWidth: "100%",
            maxHeight: "100%",
            aspectRatio: "1/1",
        }} loading="lazy" decoding="async"></img>
    );
}