import nodemon from "nodemon";
import * as fs from "node:fs";

const ignore = fs.readFileSync(".gitignore", { encoding: "utf-8" })
    .split("\n")
    .filter(s => s.length > 0);

nodemon({
    script: "build.js",
    ignore,
    watch: ["./src", "./static"]
}).on("restart", files => {
    console.log(files);
});