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
  "http://im.just.memi.ng" 3<&0 4>/dev/null

# http://im.just.memi.ng
# http://localhost
# http://cancri-sp.fly.dev
