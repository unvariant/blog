import Image from './Image.js';
import { useInfo } from '../../../components/InfoContext.js';

const imageFormats = [
    ".jpg",
    ".jpeg",
    ".png",
    ".webp",
];

export default function (props) {
    const info = useInfo();
    const target = info.parent.children.find(i => i.filename == props.target);
    const main = target.children.filter(i => imageFormats.indexOf(i.extname) != -1).map(i => (
        <Image src={ `${props.target}/${i.filename}` }></Image>
    ));
    const practice = target.children.find(i => i.filename == "practice").children.map(i => (
        <Image src={ `${props.target}/practice/${i.filename}` }></Image>
    ));

    return (
            <div style={{
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
            }} className="fullwidth">
                { props.mainTitle }
                <div style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(3, 1fr)",
                    rowGap: "5px",
                    columnGap: "5px",
                    gridAutoRows: "min-content",
                    boxSizing: "border-box",
                }} className="fullwidth">
                    { main }
                </div>
                { props.practiceTitle }
                <div style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(6, 1fr)",
                    rowGap: "5px",
                    columnGap: "5px",
                    gridAutoRows: "min-content",
                    boxSizing: "border-box",
                }} className="fullwidth">
                    { practice }
                </div>

                <div>
                    <label>
                        <div>
                            <input type="radio" name="gallery"></input>
                            <div class="hide close"></div>
                        </div>
                    </label>
                </div>
            </div>
    );
}