# blog

expect stuff to not work.

## building

```console
npm run build
```

Will build the entire blog and place the output into the `_build/` directory.

## development

```console
npm run dev
```

Currently uses nodemon which reruns the entire build script when changes are detected. Hot reloading is in the works but doesnt work right now.

## custom patches

### import-jsx
With node 22 importing JSON files changed from `assert { type: "json" }` to `with { type: "json" }`. The more portable way of doing this is to `JSON.parse(fs.readFile(...))` which works pre and post node 22.