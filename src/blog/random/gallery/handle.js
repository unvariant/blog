import { Worker } from "node:worker_threads";

export const optimizer = new Worker("./src/blog/random/gallery/optimizer.js");