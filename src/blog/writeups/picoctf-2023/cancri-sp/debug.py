from pwn import *
from pwnc.gdb.new_launch import debug, HexInt

def find(pattern: bytes | list[bytes], limit: int = 0, perm: str = "r??", align: int = 1):
    if type(pattern) == bytes:
        search = f"--hex {pattern.hex()}"
    elif type(pattern) == list:
        patterns = "|".join(p.hex() for p in pattern)
        search = f"--hex-regex {patterns}"
    else:
        raise TypeError("unknown pattern type")

    ret = g.execute(f"find {search} -l {limit} -p {perm} -a {align}", to_string=True)
    locs = []
    for line in ret.splitlines():
        parts = line.split(":", maxsplit=1)
        if len(parts) <= 1:
            continue

        locs.append(HexInt(parts[0], 0))

    if limit == 1 and len(locs) == 1:
        return locs[0]
    return locs

context.terminal = ["kitty"]

g, p = debug("./dev.sh")

g.wait_for_stop()
g.execute("set breakpoint pending on")
g.execute("b ChromeMain")
g.continue_and_wait()
g.execute("b *'storage::BlobRegistryImpl::Register(mojo::PendingReceiver<blink::mojom::Blob>, std::Cr::basic_string<char, std::Cr::char_traits<char>, std::Cr::allocator<char> > const&, std::Cr::basic_string<char, std::Cr::char_traits<char>, std::Cr::allocator<char> > const&, std::Cr::basic_string<char, std::Cr::char_traits<char>, std::Cr::allocator<char> > const&, std::Cr::vector<mojo::StructPtr<blink::mojom::DataElement>, std::Cr::allocator<mojo::StructPtr<blink::mojom::DataElement> > >, base::OnceCallback<void ()>)' + 0x175")
g.execute("ignore 2 1029")
# g.execute("b RequestHandlerImpl::OnReceiveResponse(mojo::StructPtr<network::mojom::URLResponseHead>, mojo::ScopedHandleBase<mojo::DataPipeConsumerHandle>, absl::optional<mojo_base::BigBuffer>)")
g.execute("file ./src/out/Final/chrome")
# g.execute("brva 0x0efff686")
g.continue_and_wait()

contents = find(b"LES-AMATEURS", limit=31, align=0x100, perm="rw?")
print(len(contents))
blobs = dict()
for ptr in contents:
    idx = int(g.read_memory(ptr, 15)[13:], 16)
    blobs[idx] = find(p64(ptr), limit=1, align=0x10, perm="rw?")

prev = None
for idx, blob in sorted(blobs.items()):
    if prev:
        diff = f", diff = {blob-prev:#x}"
    else:
        diff = ""
    log.info(f"blob[0x{idx:02x}] = {blob}{diff}")
    prev = blob

"""
  0x22dc0134e460:    4c 45 53 2d 41 4d 41 54  45 55 52 53 ab ab ab ab    |  LES-AMATEURS....  |
  0x22dc0134e560:    4c 45 53 2d 41 4d 41 54  45 55 52 53 ab ab ab ab    |  LES-AMATEURS....  |
  0x22dc0134e660:    4c 45 53 2d 41 4d 41 54  45 55 52 53 ab ab ab ab    |  LES-AMATEURS....  |
  0x22dc0134e760:    4c 45 53 2d 41 4d 41 54  45 55 52 53 ab ab ab ab    |  LES-AMATEURS....  |
  0x22dc0134e860:    4c 45 53 2d 41 4d 41 54  45 55 52 53 ab ab ab ab    |  LES-AMATEURS....  |
  0x22dc0134e960:    4c 45 53 2d 41 4d 41 54  45 55 52 53 ab ab ab ab    |  LES-AMATEURS....  |
  0x22dc0134ea60:    4c 45 53 2d 41 4d 41 54  45 55 52 53 ab ab ab ab    |  LES-AMATEURS....  |
  0x22dc0134eb60:    4c 45 53 2d 41 4d 41 54  45 55 52 53 ab ab ab ab    |  LES-AMATEURS....  |
  0x22dc0134ed60:    4c 45 53 2d 41 4d 41 54  45 55 52 53 ab ab ab ab    |  LES-AMATEURS....  |
  0x22dc0134ed80:    4c 45 53 2d 41 4d 41 54  45 55 52 53 ab ab ab ab    |  LES-AMATEURS....  |
"""

p.interactive()
