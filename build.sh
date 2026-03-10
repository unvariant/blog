#!/bin/bash

set -e

path=$(dirname "$(readlink -f "$0")")
name=$(basename "$0")
work="/root"
cmd="$1"
shift

function sandbox() {
    docker run --rm \
    -v "$PWD:$work:ro" \
    -v "$PWD/node_modules:$work/node_modules" \
    -v "$PWD/package-lock.json:$work/package-lock.json" \
    -v "$PWD/.npmrc:$work/.npmrc" \
    -v "$PWD/_cache:$work/_cache" \
    -v "$PWD/_build:$work/_build" \
    -w "$work" \
    -it blog \
    "$@"
}

if [ -z "$cmd" ]; then
    echo "usage: $name [setup|build]"
    exit 1
fi

cd "$path"

case "$cmd" in
    setup)
    docker build . -t blog
    sandbox npm config set update-notifier false
    sandbox npm i
    ;;

    build)
    sandbox npm run build
    ;;

    dev)
    sandbox npm run dev
    ;;

    lint)
    sandbox ./src/scripts/lint.sh "$@"
    ;;

    shell)
    sandbox bash
    ;;
esac