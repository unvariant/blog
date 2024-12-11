import hljs from "highlight.js/lib/core"
import { languages } from "./languages.js"

for (const [langname, langdef] of Object.entries(languages)) {
    hljs.registerLanguage(langname, langdef)
}

export default hljs
