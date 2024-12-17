import { useInfo } from "#components/Context.js";
import path from "node:path";
import { optimizer } from "./handle.js";
import sizeOf from "image-size";
import { execSync } from "node:child_process";

export default function (props) {
    const info = useInfo();
    const src = path.join(info.dirname, props.src);
    const sizeSet = props.sizeSet || "30vw";
    const basename = path.basename(src, path.extname(src));
    const altText = props.alt || "oops";
    const target = `${props.target}-gallery`;
    const optimize = props.optimize || false;

    let webps = [];
    let jpegs = [];
    if (optimize) {
        let dimensions = undefined;
        try {
            dimensions = sizeOf(src);
        } catch (e) {
            console.log(`error reading dimensions with image-size: ${e}`);
        }
        if (dimensions === undefined) {
            try {
                console.log(`slow path using file...`);
                const output = execSync(`file ${src}`);
                const parts = /([0-9]+)x([0-9]+)/.exec(output);
                const dims = [parseInt(parts[1]), parseInt(parts[2])];
                if (
                    typeof dims[0] === "number" &&
                    typeof dims[1] === "number"
                ) {
                    dimensions = {
                        width: dims[0],
                        height: dims[1],
                    };
                } else {
                    console.log(
                        `failed to parse image size from file output: ${output}`
                    );
                }
            } catch (e) {
                console.log(`error reading dimensions with file: ${e}`);
            }
        }
        if (dimensions === undefined) {
            throw new Error("failed to find image size");
        }
        const sizes = [400, 800, 1440].map((width) => [
            width,
            Math.round((dimensions.height * width) / dimensions.width),
        ]);
        const formats = ["WEBP", "JPG"];

        optimizer.postMessage({
            file: src,
            sizes,
            formats,
        });

        webps = sizes
            .map(
                (dims) =>
                    `/optimized-images/${basename}/${dims[0]}x${dims[1]}.webp ${dims[0]}w`
            )
            .join(", ");
        jpegs = sizes
            .map(
                (dims) =>
                    `/optimized-images/${basename}/${dims[0]}x${dims[1]}.jpg ${dims[0]}w`
            )
            .join(",");
    }

    const img = (
        <picture>
            <source type="image/webp" srcset={webps}></source>
            <img
                src={`${props.src}/raw`}
                srcset={jpegs}
                sizes={sizeSet}
                alt={altText}
                style={{
                    aspectRatio: "1/1",
                    objectFit: "scale-down",
                    maxWidth: "100%",
                }}
                decoding="async"
            ></img>
        </picture>
    );

    if (props.target === undefined) {
        return img;
    }

    return (
        <label>
            <input type="radio" name={target} class="gallery"></input>
            {img}
            <div class="hide left">
                <span
                    style={{
                        writingMode: "vertical-rl",
                        textOrientation: "upright",
                    }}
                >
                    LEFT
                </span>
            </div>
            <div class="hide right">
                <span
                    style={{
                        writingMode: "vertical-rl",
                        textOrientation: "upright",
                    }}
                >
                    RIGHT
                </span>
            </div>
        </label>
    );
}
