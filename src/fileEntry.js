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

}

export default function(info) {
    const style = {
        display: "flex",
        justifyContent: "space-between",
        fontFamily: "JetBrains Mono, monospace",
    };
    if (info.stats.isFile()) {
        let newExtName = ".html";
        let converted = `${info.filename}${newExtName}`;

        if (info.basename == "index") {
            converted = "index.html";
        }

        return (
            <div key={converted} className="file" style={ style }>
                <a href={converted}>🗎 {info.filename}</a>
                <div style={{ display: "flex-inline", justifyContent: "space-evenly" }}>
                    <span>{ apacheDate(info.lastModifiedDate) }</span>
                    <span>{ info.size }</span>
                </div>
            </div>
        );
    } else if (info.stats.isDirectory()) {
        return (
            <div key={info.basename} className="file" style={ style }>
                <a href={info.basename}>📁 {info.basename}</a>
                <div style={{ display: "flex-inline", justifyContent: "space-evenly" }}>
                    <span>{ apacheDate(info.lastModifiedDate) }</span>
                    <span>{ info.size }</span>
                </div>
            </div>
        );
    }
}