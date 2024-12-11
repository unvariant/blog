#!/bin/sh

FILES="./src/**/*.mdx package.json src/utils src/plugins src/loaders src/bun-loaders src/build.js src/components.js src/highlight.js src/languages.js src/processor.js src/render.js"

if [ -z "${1}" ]; then
    echo "usage - lint.sh [check|write]"
    exit 1
elif [[ "check" == "${1}" ]]; then
    echo "checking"
    npx prettier --check ${FILES}
fi