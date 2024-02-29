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

function grabIcon(stats) {
    if (stats.isFile()) {
        return "/icons/text.png";
    } else if (stats.isDirectory()) {
        return "/icons/dir.png";
    } else {
        // TODO: get a dont know icon
        return "/icons/text.png";
    }
}

export default function(info, options) {
    const wantsMeta = options.hasOwnProperty("meta") ? options.meta : true;

    const meta = wantsMeta ? (
        <div className="file-meta">
            <span>{ "\u200E" }</span>
            <span>{ formatSize(info.size) }</span>
            <span className="file-meta-date">{ apacheDate(info.lastModifiedDate) }</span>
        </div>
    ) : <></>;

    const icon = grabIcon(info.stats);
    const linkpath = `/${info.relativePath}/`;
    const filename = options.filename || info.filename;

    return (
        <div key={linkpath} className="file">
            <a href={linkpath} className="file-link">
                <img src={icon}></img>
                <span>{filename}</span>
            </a>
            { meta }
        </div>
    );
}