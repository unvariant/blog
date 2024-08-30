import { useInfo } from "../../../components/InfoContext.js";
import path from "node:path";
import { optimizer } from "./handle.js";
import sizeOf from "image-size";

export default function(props) {
    const info = useInfo();
    const src = path.join(info.dirname, props.src);
    const sizeSet = props.sizeSet || "30vw";
    const basename = path.basename(src, path.extname(src));
    const altText = props.alt || "oops";

    const dimensions = sizeOf(src);
    const sizes = [400, 800, 1440].map(width => [width, Math.round(dimensions.height * width / dimensions.width)]);
    const formats = ["WEBP", "JPG"];
    
    optimizer.postMessage({
        file: src,
        sizes,
        formats,
    });

    const webps = sizes.map(dims => `/optimized-images/${basename}/${dims[0]}x${dims[1]}.webp ${dims[0]}w`).join(", ");
    const jpegs = sizes.map(dims => `/optimized-images/${basename}/${dims[0]}x${dims[1]}.jpg ${dims[0]}w`).join(",");

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