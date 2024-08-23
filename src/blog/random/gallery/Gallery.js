import Image from './Image.js';

export default function (props) {
    const target = props.info.parent.children.find(i => i.filename == props.target);
    const main = target.children.filter(i => i.extname == ".jpg").map(i => (
        <Image src={ `${props.target}/${i.filename}/raw` }></Image>
    ));
    const practice = target.children.find(i => i.filename == "practice").children.map(i => (
        <Image src={ `${props.target}/practice/${i.filename}/raw` }></Image>
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
        </div>
    );
}