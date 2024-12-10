import { useInfo } from "./Context.js";
import FileEntry from "./FileEntry.js";

export default function (props) {
    const info = useInfo();

    return (
        <>
            {info.children
                .filter((info) => info.stats.isDirectory())
                .sort((a, b) => a.filename.localeCompare(b.filename))
                .map(FileEntry)}
            {info.children
                .filter(
                    (info) => info.stats.isFile() || info.stats.isSymbolicLink()
                )
                .sort((a, b) => a.filename.localeCompare(b.filename))
                .map(FileEntry)}
        </>
    );
}
