import * as path from "node:path";

function apacheDate(date) {
    const year = date.getFullYear();
    const month = (date.getMonth() + 1).toString().padStart(2, "0");
    const day = date.getDate().toString().padStart(2, "0");
    const hour = date.getHours().toString().padStart(2, "0");
    const minute = date.getMinutes().toString().padStart(2, "0");
    return `${year}-${month}-${day} ${hour}:${minute}`;
}

function formatSize(size) {
    let suffixList = ['KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB', 'YiB'];
    let threshold = 1024;
    if (size < threshold) {
        return `${size} bytes`;
    } else {
        for (let i = 0; i < suffixList.length; i++) {
            const div = size / threshold;
            if (div < threshold) {
                return `${div.toFixed(0)} ${suffixList[i]}`;
            }
            threshold *= 1024;
        }
    }
}

export default function(info, options) {
    const wantsMeta = options.hasOwnProperty("meta") ? options.meta : true;

    const style = {
        display: "flex",
        justifyContent: "space-between",
        fontFamily: "JetBrains Mono, monospace",
        marginBottom: "0.5rem",
    };

    const meta = wantsMeta ? (
        <div style={{ display: "flex-inline", justifyContent: "space-evenly" }}>
            <span>{ formatSize(info.size) }</span>
            <span style={{ marginLeft: "1rem" }}>{ apacheDate(info.lastModifiedDate) }</span>
        </div>
    ) : <></>;

    if (info.stats.isFile()) {
        let newExtName = ".html";
        let converted = `${info.filename}${newExtName}`;

        if (info.basename == "index") {
            converted = "index.html";
        }

        return (
            <div key={converted} className="file" style={ style }>
                <a href={converted} style={{ display: "inline-flex", "alignItems": "center" }}>
                    <img src="/icons/text.png" style={{ paddingRight: "1rem" }}></img>
                    {info.filename}
                </a>
                { meta }
            </div>
        );
    } else if (info.stats.isDirectory()) {
        return (
            <div key={info.basename} className="file" style={ style }>
                <a href={info.basename} style={{ display: "inline-flex", "alignItems": "center" }}>
                    <img src="/icons/dir.png" style={{ paddingRight: "1rem" }}></img>
                    <span>{info.basename}</span>
                </a>
                { meta }
            </div>
        );
    }
}