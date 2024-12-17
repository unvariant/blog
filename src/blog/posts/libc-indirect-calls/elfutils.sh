#!/bin/sh

docker run --rm -w /share -v "$PWD":/share -it elfutils $@