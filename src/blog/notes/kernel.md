## access physical memory in gdb
`monitor px/16g [addr]`

## dump kernel memory map
`vmmap`
`pagewalk`
- user page table is KERNEL_CR3 | 0x1000

## dump kallsyms
`ksymaddrs-remote`
`ksymaddrs-remote-apply`

## page_offset_base
- symbol defined in kallsyms, the first qword at this address points to the physmap

## physmap
- a region of mmeory that is a 1:1 mapping of physical memory
- affected by KASLR

## cpu_entry area
- a part of the kernel that always resides at a fixed address, regardless of KASLR
- always at `0xfffffe0000000000`

## ldt region
- mapped KERNEL R-- in both user and kernel page tables
- mapped at the same fixed address in both page tables
- readable and writable using `modify_ldt`

## KASLR leaks
- any sort of memory access side channel
- prefetch, maskmov, etc
- with KASLR the syscall trampoline must present in the page table
- kernel < 6.7, leak from /sys/kernel/notes
- leak from dmesg

## qemu `-hda`
- contents of `-hda` end at phys addr `0xbfe00000`, scan down at page increments to leak contents

## cross cache
- [https://ruia-ruia.github.io/2022/08/05/CVE-2022-29582-io-uring/#crossing-the-cache-boundary](https://ruia-ruia.github.io/2022/08/05/CVE-2022-29582-io-uring/#crossing-the-cache-boundary)

## KALSR

## SMAP

## SMEP

## FGKALSR

## ret2usr

## ret2dir

## modprobe overwrite

## dirty pipe

## dirty cred

## namespace escapes
