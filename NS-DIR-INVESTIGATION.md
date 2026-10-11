# Why /proc/<pid>/ns/{pid,ipc} never appear on the MTK device

This branch keeps every write route that was tried while chasing one symptom, so
the dead ends do not have to be walked again. The clean, PR-sized version of the
work is on `dsh/6.18-fixes`; this branch is the notebook.

Device: M367FC / yingtian, HyperOS 4.0.11.0.XBMCNXM, Android 17 (SDK 37)
Kernel: 6.18.21-android17-5-g1d099fcb35e0-abogki538445360-4k
        CONFIG_PID_NS=n, CONFIG_IPC_NS=n, CONFIG_USER_NS=n, CONFIG_SYSVIPC=n,
        CONFIG_POSIX_MQUEUE=n, CONFIG_ARM64_BTI=y, CONFIG_ARM64_BTI_KERNEL=y,
        CONFIG_STRICT_KERNEL_RWX=y, CONFIG_KALLSYMS_ALL=y

Everything else the module provides works on this device: SysV IPC, POSIX
mqueue, `unshare(CLONE_NEWPID)` with the child reading pid 1, NSpid lines in
/proc/<pid>/status, `unshare(CLONE_NEWIPC)`. The functional test scores 26/2
in the good case and the two failures are always these two entries.

## The symptom

`droid_lkm_proc_init()` writes `droid_lkm_ns_lookup` into
`proc_ns_dir_inode_operations.lookup` and the write reports success. The field
keeps its old value, the hook is never entered, and every read of
`/proc/<pid>/ns/pid` answers ENOENT. Fresh procfs mounts behave the same way,
so it is not a negative dcache entry.

Two things were confirmed correct first:

* `droid_lkm_sym("proc_ns_dir_inode_operations")` returns the address that
  `/proc/kallsyms` reports, and `kern_path("/proc/self/ns")` returns the same
  `i_op` pointer, so the struct being patched is the one the VFS uses;
* the value read out of it before the write is `proc_ns_dir_lookup`, the same
  address `/proc/kallsyms` reports for that symbol.

## Route 1: the kernel's own patcher

`droid_lkm_patch_write()` -> `hk_patch_write` -> `hk_write_kernel` ->
`aarch64_insn_patch_text` -> `patch_map`:

```c
static void *patch_map(void *addr, int fixmap)
{
	if (is_image_text((unsigned long)addr)) {
		phys = __pa_symbol(addr);
	} else {
		struct page *page = vmalloc_to_page(addr);
		BUG_ON(!page);
		phys = page_to_phys(page) + offset_in_page(addr);
	}
	return (void *)set_fixmap_offset(fixmap, phys);
}
```

`.rodata` is not `is_image_text()`, so this goes through `vmalloc_to_page` and
writes through the `FIX_TEXT_POKE0` alias. It returns 0 and the field does not
change.

## Route 2: the library's own fixmap writer

`hk_write_fixmap()` -> `hk_write_fixmap_by()` -> `hk_patch_slot_run()`, which
translates with the library's own `init_mm` walk and opens its own slot
`FIX_BTMAP_END`:

```c
phys = to_pa(addr);
ret = call_set_fixmap(idx, phys & PAGE_MASK, PAGE_KERNEL);
dst = __fix_to_virt(idx) + (phys & ~PAGE_MASK);
memcpy((void *)dst, src, chunk);
```

Independent translation, different fixmap slot, same result: returns 0, field
unchanged. The library is not at fault here, and its walk is not either: see
route 3.

## Route 3: the linear alias

Both routes above end in a fixmap alias, so the next thing to remove was the
fixmap. `hk_va_to_pa()` gives the physical address, the linear alias is
`(pa - memstart_addr) | PAGE_OFFSET`, and the store is a plain `memcpy`.

Before judging that alias, the same word was read through it and through the
image address:

```
proc ns hook: alias ffffff8001fbfe00 and image both read ffffffdaf2a98180, the translation agrees
proc ns hook: the linear alias ffffff8001fbfe00 is read only too
```

So the translation is right, the physical page is right, and the linear mapping
of that page is read only as well, which is what `rodata_full` means. The store
was never attempted, because a plain store to a read only page is a fault with
no way back.

## Route 4: open the direct map

`set_direct_map_default_noflush()` is the only primitive in the kernel that
touches a direct map PTE, and it is gated on the same `rodata_full` flag that
made the alias read only, so it would have been willing to flip the page:

```c
int set_direct_map_default_noflush(struct page *page)
{
	pgprot_t set_mask = __pgprot(PTE_PRESENT_VALID_KERNEL | PTE_WRITE);
	pgprot_t clear_mask = __pgprot(PTE_PRESENT_INVALID | PTE_RDONLY);

	if (!can_set_direct_map())
		return 0;

	return update_range_prot((unsigned long)page_address(page), PAGE_SIZE,
				 set_mask, clear_mask);
}
```

It is behind `ns_force=1` on this branch, because it leaves the page writable in
the direct map afterwards and there is no exported primitive to put the PTE
back. On this device it never runs:

```
proc ns force: set_direct_map_default_noflush is without a bti landing pad, cannot call it
```

The function exists, but its export is trimmed from the GKI symbol list, so
nothing ever takes its address and it carries no `bti c`. Calling it through a
pointer would raise a BTI exception, which is fatal. `droid_lkm_indirect_callable()`
refuses it, which is exactly what that helper is for.

## The control group

The same device, the same load, the same `droid_lkm_patch_write()`, the same
`.rodata` section: the `sys_call_table` writes do land. `droid_lkm_slot_patch()`
now reads each slot back and reports `slot %d did not take` when it does not;
on this device no slot ever reports that, and `unshare`/`clone` interception is
demonstrably live.

So this is not symbol resolution, not the section, not the cache, and not the
translation. Two independent fixmap writers report success and the page does not
change, while another page in the same section takes the same call. That points
below EL1, and there is no route left that stays inside the kernel.

## What the module does about it

* tries the engine writer, then the library writer, then the linear alias, and
  reads the field back after each;
* when none of them lands it says so by name -
  `this kernel will not take the ns dir hook ... /proc/<pid>/ns/{pid,ipc} stay absent`
  - instead of logging a hook it did not install;
* does not call `try_module_get()` for a hook that is not there, and the exit
  path follows the same flag, so `rmmod` works and the module no longer needs a
  reboot to be replaced;
* keeps loading, because losing two entries is not a reason to lose the rest.

## Open observation

On the device the trimmed build (`dsh/6.18-fixes`, 6 changed files) scored
26/2 in one run and 21/3 in another, the extra failure being
`mq_open errno=38 (Function not implemented)`. A module built from an earlier
state of this branch scored 26/2 twice in the same session. The runs are not
comparable enough to call it a regression: the second 21/3 run followed a load
that had already been unloaded once, `rmmod` was hitting the keepalive pin, and
the A/B that was supposed to settle it could not reload the module. It should be
re-measured on a clean boot before this branch is trusted.
