#!/bin/bash

FILES=("package.json" "src/utils" "src/plugins" "src/loaders" "src/bun-loaders" "src/build.js" "src/components.js" "src/highlight.js" "src/shiki.js" "src/processor.js" "src/render.js")

if [[ "check" == "${1}" ]]; then
    echo "checking"
    npx prettier --check ${FILES[*]}
elif [[ "write" == "${1}" ]]; then
    echo "formatting"
    npx prettier --write ${FILES[*]}
else
    echo "usage - lint.sh [check|write]"
    exit 1
fi