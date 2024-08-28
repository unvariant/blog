import { useInfo } from "../../../components/InfoContext.js";
import path from "node:path";
import { optimizer } from "./handle.js";

export default function(props) {
    const info = useInfo();
    const src = path.join(info.dirname, props.src);
    const sizeSet = props.sizeSet || "30vw";
    const basename = path.basename(src, path.extname(src));
    const altText = props.alt || "oops";

    const sizes = [400, 800, 1440];
    const formats = ["WEBP", "JPG"];
    
    optimizer.postMessage({
        file: src,
        sizes,
        formats,
    });

    const webps = sizes.map(size => `/optimized-images/${basename}/${size}x${size}.webp ${size}w`).join(", ");
    const jpegs = sizes.map(size => `/optimized-images/${basename}/${size}x${size}.jpg ${size}w`).join(",");

    return (
        <label>
            <input type="radio" name="gallery" class="gallery"></input>
            <picture>
                <source
                    type="image/webp"
                    srcset={ webps }
                >
                </source>
                <img
                    src={ `${props.src}/raw` }
                    srcset={ jpegs }
                    sizes={ sizeSet }
                    alt={ altText }
                    style={{
                        aspectRatio: "1/1",
                        objectFit: "scale-down",
                        maxWidth: "100%",
                    }}
                    decoding="async"
                >
                </img>
            </picture>
            <div class="hide left">
                <span style={{
                    writingMode: "vertical-rl",
                    textOrientation: "upright",
                }}>
                    LEFT
                </span>
            </div>
            <div class="hide right">
                <span style={{
                    writingMode: "vertical-rl",
                    textOrientation: "upright",
                }}>
                    RIGHT
                </span>
            </div>
        </label>
    );
}