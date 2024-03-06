from subprocess import run

run("wat2wasm write.wat -o write.wasm", shell=True, check=True)

wasm = list(open("write.wasm", "rb").read())

print(f"""
var wasm_code = new Uint8Array({wasm})
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
""".strip("\n"))