#!/bin/sh

set -eux

exec ./src/out/Final/chrome \
  --enable-blink-features=MojoJS \
  --headless \
  --disable-gpu \
  --remote-debugging-pipe \
  --user-data-dir=/does-not-exist \
  --disable-dev-shm-usage \
  --no-sandbox \
  "localhost" 3<&0 4>/dev/null
