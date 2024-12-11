let processors = new Map()

function normalizeShortcode(shortcode) {
    if (shortcode.startsWith(".")) {
        shortcode = shortcode.slice(1)
    }

    return shortcode
}

export function register(shortcodes, processor) {
    for (let shortcode of shortcodes) {
        shortcode = normalizeShortcode(shortcode)

        processors.set(shortcode, processor)
    }
}

export async function process(shortcode, info, defaultProcessor) {
    shortcode = normalizeShortcode(shortcode)

    if (processors.has(shortcode)) {
        return processors.get(shortcode)(info)
    }

    return defaultProcessor(info)
}
