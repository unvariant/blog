# blog

expect stuff to not work. Uses docker for sandboxing. It will mount the entire folder into docker as readonly, while allowing write access to select files and directories.

## setup

```console
./build.sh setup
```

## building

```console
./build.sh build
```

Will build the entire blog and place the output into the `_build/` directory.

## development

```console
./build.sh dev
```

Currently uses nodemon which reruns the entire build script when changes are detected. Hot reloading is in the works but doesnt work right now. Doesn't actually host a server on localhost to serve the files, use your favorite webserver of choice to deploy locally. I typically use `cd _build; python3 -m http.server 8080`.

## custom patches

### import-jsx
With node 22 importing JSON files changed from `assert { type: "json" }` to `with { type: "json" }`. The more portable way of doing this is to `JSON.parse(fs.readFile(...))` which works pre and post node 22.