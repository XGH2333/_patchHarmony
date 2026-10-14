# nsprobe

the minimal module used to answer the question this directory documents. no
dependencies: every kernel address it needs arrives as a module parameter read
out of /proc/kallsyms with kptr_restrict at 0, because kallsyms_lookup_name has
no bti landing pad on this kernel and register_kprobe refuses to hand back the
address of a data symbol.

```sh
sh probe.sh    # gathers addresses, insmods in the background, prints dmesg
```

it dumps the page table entry, guarded bit and entry instruction of every
address it touches, then for each write path does: write, plain readback, and a
dc ivac readback that shows what memory itself holds. every write that touches
kernel text or rodata is undone before init returns. engine=1 enables the test
that calls the kernel's own patcher; it cannot return on this device because
stop_machine never completes there.
