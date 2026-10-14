// SPDX-License-Identifier: GPL-2.0
/*
 * nsprobe: a minimal out-of-tree lkm whose only job is to answer why a store
 * to proc_ns_dir_inode_operations.lookup does not take on this device, while
 * the same primitive reaches sys_call_table just fine.
 *
 * three questions it settles:
 *
 *  1. did the write land in memory at all? a store that no cpu ever observes
 *     and that raises no fault cannot be seen through the same cache line it
 *     was written through, so every write is followed by an `dc ivac`
 *     readback, which discards the line and refills from memory. if the value
 *     appears only after that, the write landed and the readback was stale;
 *     if it never appears, the memory system threw the store away.
 *
 *  2. did the permission flip take? the pte is read back after set_pte, so a
 *     flip that silently did nothing is reported instead of being confused
 *     with a write that failed while the pte was writable.
 *
 *  3. which write path fails? the kernel's own aarch64_insn_patch_text (what
 *     droid_lkm uses), aarch64_insn_write with no post-write cache clean (the
 *     difference between them is one dc cvau), KernelSU's exact fixmap
 *     sequence, a direct store through a flipped pte, and a control store to
 *     ordinary writable .data.
 *
 * safety: every write that touches kernel text or rodata is written, read
 * back and restored inside one stop_machine window, so no other cpu can
 * execute against a half-patched table. the stubs written into the slots
 * carry a bti landing pad (checked before they are used) and behave like the
 * value that was there: the ns lookup stub answers -ENOENT, which is exactly
 * what a missing entry answers today, so even a window in which a restore
 * failed looks like a kernel without this module.
 */
#include <linux/module.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <linux/stop_machine.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/cpumask.h>
#include <asm/ptrace.h>
#include <asm/barrier.h>
#include <asm/fixmap.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

#define NP_TAG "[nsprobe] "

typedef int (*np_insn_write_t)(void *addr, u32 insn);
typedef int (*np_patch_text_t)(void **addrs, u32 *insns, int cnt);
typedef void (*np_set_fixmap_t)(enum fixed_addresses idx, phys_addr_t phys, pgprot_t prot);
typedef int (*np_nofault_write_t)(void *dst, const void *src, size_t size);

/*
 * every symbol this module touches is handed in from user space, read out of
 * /proc/kallsyms with kptr_restrict at 0. calling kallsyms_lookup_name through
 * a pointer is not an option on this kernel: the symbol carries no bti landing
 * pad, and register_kprobe refuses to return the address of a data symbol, so
 * no kernel side resolver is reachable. a module that takes its addresses as
 * parameters needs none
 */
static unsigned long nsA, sctB, ctlC, imm, ptw, ptp, fxm, nfw, mam, msr, csf, pps;
static unsigned long engine;
module_param(engine, ulong, 0);
MODULE_PARM_DESC(engine, "1 runs the kernel patcher test last; it never returns here");
module_param(nsA, ulong, 0);
module_param(sctB, ulong, 0);
module_param(ctlC, ulong, 0);
module_param(imm, ulong, 0);
module_param(ptw, ulong, 0);
module_param(ptp, ulong, 0);
module_param(fxm, ulong, 0);
module_param(nfw, ulong, 0);
module_param(mam, ulong, 0);
module_param(msr, ulong, 0);
module_param(csf, ulong, 0);
module_param(pps, ulong, 0);
MODULE_PARM_DESC(nsA, "proc_ns_dir_inode_operations");
MODULE_PARM_DESC(sctB, "sys_call_table");
MODULE_PARM_DESC(ctlC, "kptr_restrict");
MODULE_PARM_DESC(imm, "init_mm");
MODULE_PARM_DESC(ptw, "aarch64_insn_write");
MODULE_PARM_DESC(ptp, "aarch64_insn_patch_text");
MODULE_PARM_DESC(fxm, "__set_fixmap");
MODULE_PARM_DESC(nfw, "copy_to_kernel_nofault");
MODULE_PARM_DESC(mam, "cpu_online_mask");
MODULE_PARM_DESC(msr, "memstart_addr");
MODULE_PARM_DESC(csf, "check_unshare_flags (known to bti fault)");
MODULE_PARM_DESC(pps, "proc_pid_status (known guarded)");
static np_insn_write_t np_insn_write;
static np_patch_text_t np_insn_patch_text;
static np_set_fixmap_t np_set_fixmap;
static np_nofault_write_t np_copy_to_kernel_nofault;
static const struct cpumask *np_cpu_online_mask;
static struct mm_struct *np_init_mm;

static unsigned long np_a, np_b, np_c, np_alin;	/* target addresses */
static unsigned long np_a_pa;

/* A is the ns dir lookup slot, B a syscall table slot, C a sysctl in .data */
static bool np_restore_failed_a, np_restore_failed_b;

/*
 * the two stubs. both take the landing pad check before they are written
 * anywhere, because an indirect call on a bti kernel without one is fatal
 */
static __nocfi noinline struct dentry *np_probe_lookup(struct inode *dir,
						       struct dentry *dentry,
						       unsigned int flags)
{
	return ERR_PTR(-ENOENT);
}

static __nocfi noinline long np_probe_syscall(const struct pt_regs *regs)
{
	return -ENOSYS;
}

/* ---- symbol plumbing ---------------------------------------------------- */

static bool np_callable(unsigned long addr)
{
	u32 insn = 0;

	if (!addr)
		return false;
	if (copy_from_kernel_nofault(&insn, (void *)addr, sizeof(insn)))
		return false;
	return insn == 0xd50323bf || insn == 0xd50323ff;
}

static unsigned long np_sym(const char *name)
{
	if (!strcmp(name, "init_mm"))
		return imm;
	if (!strcmp(name, "aarch64_insn_write"))
		return ptw;
	if (!strcmp(name, "aarch64_insn_patch_text"))
		return ptp;
	if (!strcmp(name, "__set_fixmap"))
		return fxm;
	if (!strcmp(name, "copy_to_kernel_nofault"))
		return nfw;
	if (!strcmp(name, "cpu_online_mask"))
		return mam;
	if (!strcmp(name, "memstart_addr"))
		return msr;
	if (!strcmp(name, "proc_ns_dir_inode_operations"))
		return nsA;
	if (!strcmp(name, "sys_call_table"))
		return sctB;
	if (!strcmp(name, "kptr_restrict"))
		return ctlC;
	return 0;
}

/* ---- page table walk ---------------------------------------------------- */

struct np_walk {
	bool ok;
	int level;		/* 0 page, 1 pud block, 2 pmd block */
	unsigned long pa;
	u64 raw;
	pte_t *ptep;
};

static struct np_walk np_walk(unsigned long va)
{
	struct np_walk w = { 0 };
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	if (!np_init_mm)
		return w;
	pgd = pgd_offset(np_init_mm, va);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return w;
	p4d = p4d_offset(pgd, va);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return w;
	pud = pud_offset(p4d, va);
	if (pud_none(*pud) || pud_bad(*pud))
		return w;
#if defined(pud_leaf)
	if (pud_leaf(*pud)) {
		w.level = 1;
		w.raw = pud_val(*pud);
		w.pa = __pud_to_phys(*pud) + (va & ~PUD_MASK);
		w.ok = true;
		return w;
	}
#endif
	pmd = pmd_offset(pud, va);
	if (pmd_none(*pmd))
		return w;
#if defined(pmd_leaf)
	if (pmd_leaf(*pmd)) {
		w.level = 2;
		w.raw = pmd_val(*pmd);
		w.pa = __pmd_to_phys(*pmd) + (va & ~PMD_MASK);
		w.ok = true;
		return w;
	}
#endif
	if (pmd_bad(*pmd))
		return w;
	w.ptep = pte_offset_kernel(pmd, va);
	if (!w.ptep || !pte_present(*w.ptep))
		return w;
	w.level = 0;
	w.raw = pte_val(*w.ptep);
	w.pa = __pte_to_phys(*w.ptep) + (va & ~PAGE_MASK);
	w.ok = true;
	return w;
}

static void np_dump(const char *tag, unsigned long va)
{
	struct np_walk w = np_walk(va);

	if (!w.ok) {
		pr_info(NP_TAG "%s va=%px walk FAILED\n", tag, (void *)va);
		return;
	}
	pr_info(NP_TAG "%s va=%px pa=0x%lx raw=0x%llx lvl=%d attr=%lu rw=%d\n",
		tag, (void *)va, w.pa, (unsigned long long)w.raw, w.level,
		(unsigned long)((w.raw >> 2) & 7),
		w.level ? 1 : pte_write(__pte(w.raw)));
}

/* ---- cache helpers (no exported symbol needed) -------------------------- */

static void np_ivac(unsigned long va)
{
	asm volatile("dsb sy" ::: "memory");
	asm volatile("dc ivac, %0" :: "r"(va & ~63UL) : "memory");
	asm volatile("dsb sy" ::: "memory");
	asm volatile("isb" ::: "memory");
}

/*
 * the data half of caches_clean_inval_pou, which aarch64_insn_patch_text runs
 * after its own store. clean pushes the cache line back to memory; if the line
 * did not take the store, this writes the old value over the new one
 */
static void np_clean_to_pou(unsigned long start, unsigned long end)
{
	unsigned long a = start & ~63UL;

	for (; a < end; a += 64)
		asm volatile("dc cvau, %0" :: "r"(a) : "memory");
	asm volatile("dsb sy" ::: "memory");
}

static u64 np_read(unsigned long va)
{
	return *(volatile u64 *)va;
}

/* read what memory holds, whatever the cache line currently says */
static u64 np_ivac_read(unsigned long va)
{
	np_ivac(va);
	return np_read(va);
}

/*
 * what is actually at the entry of a function we would have to reach with an
 * indirect branch, and whether that page enforces bti at all. the pad question
 * is only half of it: a missing pad only matters when the page carries the
 * guarded bit, so both are always logged together
 */
static void np_entry(const char *tag, unsigned long addr)
{
	struct np_walk w = np_walk(addr);
	u32 insn = 0;
	int rc;

	if (!addr) {
		pr_info(NP_TAG "entry %s: not given\n", tag);
		return;
	}
	rc = copy_from_kernel_nofault(&insn, (void *)addr, sizeof(insn));
	pr_info(NP_TAG "entry %s=%px word=0x%08x rc=%d gp=%d\n",
		tag, (void *)addr, insn, rc,
		w.ok && w.level == 0 ? (int)((w.raw >> 50) & 1) : -1);
}

/* ---- write paths -------------------------------------------------------- */

/* route 1: the kernel's own patcher, exactly what droid_lkm's engine uses */
static int np_m1(void *dst, u64 val)
{
	void *addrs[2];
	u32 insns[2];

	if (!np_insn_patch_text)
		return -ENOENT;
	addrs[0] = dst;
	addrs[1] = dst + 4;
	insns[0] = (u32)val;
	insns[1] = (u32)(val >> 32);
	return np_insn_patch_text(addrs, insns, 2);
}

/* route 2: one word at a time through the kernel's own fixmap, no post clean */
static int np_m2(void *dst, u64 val)
{
	int ret;

	if (!np_insn_write)
		return -ENOENT;
	ret = np_insn_write(dst, (u32)val);
	if (ret)
		return ret;
	return np_insn_write((char *)dst + 4, (u32)(val >> 32));
}

/* route 3: KernelSU's own sequence, fixmap opened here instead of by the kernel */
static int np_m3(void *dst, u64 val)
{
	struct np_walk w;
	void *map;
	int ret;

	if (!np_set_fixmap)
		return -ENOENT;
	w = np_walk((unsigned long)dst);
	if (!w.ok)
		return -ENOENT;
	map = (void *)(__fix_to_virt(FIX_TEXT_POKE0) + offset_in_page(w.pa));
	np_set_fixmap(FIX_TEXT_POKE0, w.pa & PAGE_MASK, PAGE_KERNEL);
	asm volatile("dsb sy" ::: "memory");
	ret = np_copy_to_kernel_nofault ?
		np_copy_to_kernel_nofault(map, &val, sizeof(val)) :
		-ENOSYS;
	asm volatile("dsb sy" ::: "memory");
	np_set_fixmap(FIX_TEXT_POKE0, 0, __pgprot(0));
	asm volatile("dsb sy" ::: "memory");
	return ret;
}

/* ---- flip a pte writable, store, put it back ---------------------------- */

static int np_flip_store(unsigned long va, u64 val, u64 *r1, u64 *r2, int *flip_ok)
{
	struct np_walk w = np_walk(va);
	pte_t old, nw;
	int ret = 0;

	*r1 = 0;
	*r2 = 0;
	*flip_ok = -1;
	if (!w.ok || w.level != 0 || !w.ptep)
		return -ENOENT;

	old = *w.ptep;
	nw = __pte((pte_val(old) | PTE_WRITE) & ~PTE_RDONLY);
	if (pte_val(nw) != pte_val(old)) {
		set_pte(w.ptep, nw);
		dsb(ishst);
		__flush_tlb_kernel_pgtable(va);
	}
	/* did the permission change actually take? */
	*flip_ok = (pte_val(*w.ptep) == pte_val(nw)) ? 1 : 0;

	if (!pte_write(*w.ptep)) {
		/*
		 * a store through a read only mapping faults, and a fault here
		 * would kill the load before anything is logged, so a flip that
		 * did not take is a reported result, not a reason to try anyway
		 */
		*r1 = np_read(va);
		*r2 = np_ivac_read(va);
		ret = -EPERM;
		goto put_back;
	}

	*(volatile u64 *)va = val;
	dsb(ish);
	*r1 = np_read(va);
	/* memory's answer, whatever the cache line says */
	*r2 = np_ivac_read(va);

put_back:
	set_pte(w.ptep, old);
	dsb(ishst);
	__flush_tlb_kernel_pgtable(va);
	if (pte_val(*w.ptep) != pte_val(old))
		ret = ret ? ret : -EIO;
	return ret;
}

/* ---- one write / read / restore cycle ----------------------------------- */

static void np_cycle(const char *tag, void *dst, u64 orig, u64 marker,
		     int (*writer)(void *dst, u64 val), bool *restore_failed)
{
	u64 r1, r2, back;
	int wrc, rrc = -1;
	bool landed;

	wrc = writer(dst, marker);
	r1 = np_read((unsigned long)dst);
	r2 = np_ivac_read((unsigned long)dst);
	landed = (r1 == marker) || (r2 == marker);

	pr_info(NP_TAG "%s: write rc=%d read=0x%llx ivac_read=0x%llx %s\n",
		tag, wrc, (unsigned long long)r1, (unsigned long long)r2,
		landed ? "LANDED" : "not in memory");

	if (!landed)
		return;

	/* put the original back the same way it went in, then prove it */
	rrc = writer(dst, orig);
	back = np_ivac_read((unsigned long)dst);
	if (back != orig) {
		pr_err(NP_TAG "%s: RESTORE FAILED rc=%d back=0x%llx want=0x%llx\n",
		       tag, rrc, (unsigned long long)back, (unsigned long long)orig);
		if (restore_failed)
			*restore_failed = true;
	} else {
		pr_info(NP_TAG "%s: restored (rc=%d)\n", tag, rrc);
	}
}

/* ---- phases ------------------------------------------------------------- */

/* phase 1: aarch64_insn_patch_text carries its own stop_machine, so it runs
 * outside ours; nested stop_machine would deadlock
 */
static void np_phase_engine(void)
{
	np_cycle("M1/B sys_call_table", (void *)np_b, np_read(np_b),
		 (u64)np_probe_syscall, np_m1, &np_restore_failed_b);
	np_cycle("M1/A ns_lookup    ", (void *)np_a, np_read(np_a),
		 (u64)np_probe_lookup, np_m1, &np_restore_failed_a);
}

struct np_phase2 {
	u64 a, b, c;		/* originals */
	int flip_ok_a, flip_ok_ret_a, flip_ok_alin, flip_restore_a;
	u64 flip_r1_a, flip_r2_a, flip_r1_alin, flip_r2_alin;
	bool b_pte_writable;
};

static int np_phase2_cb(void *arg)
{
	struct np_phase2 *p = arg;

	/* control: ordinary writable .data, plain store, no fixmap */
	{
		u64 nc = p->c ? 0 : 1;

		*(volatile u64 *)np_c = nc;
		dsb(ish);
		pr_info(NP_TAG "C/control plain store: read=0x%llx ivac=0x%llx %s\n",
			(unsigned long long)np_read(np_c),
			(unsigned long long)np_ivac_read(np_c),
			np_read(np_c) == nc ? "LANDED" : "not in memory");
		*(volatile u64 *)np_c = p->c;
		dsb(ish);
		pr_info(NP_TAG "C/control restored: 0x%llx\n", (unsigned long long)np_read(np_c));
	}

	/* B without any permission help, if its page already allows it */
	p->b_pte_writable = pte_write(__pte(np_walk(np_b).raw));
	if (p->b_pte_writable) {
		*(volatile u64 *)np_b = (u64)np_probe_syscall;
		dsb(ish);
		pr_info(NP_TAG "B plain store: read=0x%llx %s\n",
			(unsigned long long)np_read(np_b),
			np_read(np_b) == (u64)np_probe_syscall ? "LANDED" : "not in memory");
		*(volatile u64 *)np_b = p->b;
		dsb(ish);
	}

	np_cycle("M2/A insn_write  ", (void *)np_a, p->a,
		 (u64)np_probe_lookup, np_m2, &np_restore_failed_a);

	/*
	 * the same write followed by the clean the kernel's own patcher does
	 * right after it. if the write lands and this clean puts the old value
	 * back, the engine's failure is that clean writing a line that never saw
	 * the store over the memory that did
	 */
	{
		u64 c1, c2;
		int wrc = np_m2((void *)np_a, (u64)np_probe_lookup);

		np_clean_to_pou(np_a, np_a + 8);
		c1 = np_read(np_a);
		c2 = np_ivac_read(np_a);
		pr_info(NP_TAG "M2+cvau/A: write rc=%d read=0x%llx ivac=0x%llx %s\n",
			wrc, (unsigned long long)c1, (unsigned long long)c2,
			(c1 == (u64)np_probe_lookup || c2 == (u64)np_probe_lookup) ?
			"LANDED" : "old value is back / never there");
		if (c1 == (u64)np_probe_lookup || c2 == (u64)np_probe_lookup) {
			if (np_m2((void *)np_a, p->a) ||
			    np_ivac_read(np_a) != p->a) {
				pr_err(NP_TAG "M2+cvau/A: RESTORE FAILED\n");
				np_restore_failed_a = true;
			}
		}
	}

	np_cycle("M3/A fixmap(KSU) ", (void *)np_a, p->a,
		 (u64)np_probe_lookup, np_m3, &np_restore_failed_a);

	/* flip the pte of A and store in place */
	p->flip_ok_ret_a = np_flip_store(np_a, (u64)np_probe_lookup,
					 &p->flip_r1_a, &p->flip_r2_a,
					 &p->flip_ok_a);
	if (p->flip_r1_a == (u64)np_probe_lookup || p->flip_r2_a == (u64)np_probe_lookup) {
		u64 rr1, rr2;
		int rfok;

		p->flip_restore_a = np_flip_store(np_a, p->a, &rr1, &rr2, &rfok);
		pr_info(NP_TAG "flip/A restore: rc=%d flip_ok=%d value now=0x%llx\n",
			p->flip_restore_a, rfok, (unsigned long long)np_ivac_read(np_a));
	}
	pr_info(NP_TAG "flip/A: flip_ok=%d rc=%d r1=0x%llx ivac_r2=0x%llx\n",
		p->flip_ok_a, p->flip_ok_ret_a, (unsigned long long)p->flip_r1_a,
		(unsigned long long)p->flip_r2_a);

	/* same experiment through the linear alias of the same page */
	{
		unsigned long lin = np_alin;
		u64 r1 = 0, r2 = 0;
		int fok = 0, ret;

		if (lin) {
			ret = np_flip_store(lin, (u64)np_probe_lookup, &r1, &r2, &fok);
			p->flip_ok_alin = fok;
			p->flip_r1_alin = r1;
			p->flip_r2_alin = r2;
			if (r1 == (u64)np_probe_lookup || r2 == (u64)np_probe_lookup) {
				u64 junk1, junk2;

				np_flip_store(lin, p->a, &junk1, &junk2, &(int){0});
			}
			pr_info(NP_TAG "flip/A linear: flip_ok=%d r1=0x%llx ivac_r2=0x%llx ret=%d after=0x%llx\n",
				fok, (unsigned long long)r1, (unsigned long long)r2, ret,
				(unsigned long long)np_ivac_read(np_a));
		}
	}
	return 0;
}

static int __init np_init(void)
{
	struct np_phase2 p = { 0 };
	int pad_write, pad_patch, pad_fx, pad_nw, pad_lk, pad_sys;

	pr_info(NP_TAG "loading, addresses come in as parameters\n");

	if (!nsA || !sctB || !ctlC || !imm || !ptw || !ptp || !msr) {
		pr_err(NP_TAG "missing parameters: nsA=%px sctB=%px ctlC=%px imm=%px ptw=%px ptp=%px msr=%px\n",
		       (void *)nsA, (void *)sctB, (void *)ctlC, (void *)imm,
		       (void *)ptw, (void *)ptp, (void *)msr);
		return -EINVAL;
	}

	np_init_mm = (struct mm_struct *)np_sym("init_mm");
	np_insn_write = (np_insn_write_t)np_sym("aarch64_insn_write");
	np_insn_patch_text = (np_patch_text_t)np_sym("aarch64_insn_patch_text");
	np_set_fixmap = (np_set_fixmap_t)np_sym("__set_fixmap");
	np_copy_to_kernel_nofault = (np_nofault_write_t)np_sym("copy_to_kernel_nofault");
	/* a plain exported struct, declared by cpumask.h, no parameter needed */
	np_cpu_online_mask = cpu_online_mask;

	/*
	 * the pad check is advisory from here on. this kernel is built with
	 * -mbranch-protection=standard, so a function whose address nothing takes
	 * starts at paciasp and carries no bti, and droid_lkm reaches
	 * aarch64_insn_patch_text that way all the time without faulting: what
	 * decides whether an indirect branch may land there is the guarded bit of
	 * the page, which np_entry prints next to the word
	 */
	pad_write = np_callable((unsigned long)np_insn_write);
	pad_patch = np_callable((unsigned long)np_insn_patch_text);
	pad_fx = np_callable((unsigned long)np_set_fixmap);
	pad_nw = np_callable((unsigned long)np_copy_to_kernel_nofault);

	pr_info(NP_TAG "init_mm=%px cpu_online_mask=%px\n", np_init_mm, (void *)np_cpu_online_mask);
	pr_info(NP_TAG "pads: insn_write=%d patch_text=%d set_fixmap=%d nofault_write=%d\n",
		pad_write, pad_patch, pad_fx, pad_nw);

	np_a = np_sym("proc_ns_dir_inode_operations");
	np_b = np_sym("sys_call_table");
	np_c = np_sym("kptr_restrict");
	if (!np_a || !np_b || !np_c) {
		pr_err(NP_TAG "missing symbols a=%px b=%px c=%px\n",
		       (void *)np_a, (void *)np_b, (void *)np_c);
		return -ENOENT;
	}
	/* B is a whole table; use the reboot slot as the control */
	np_b += 142UL * sizeof(unsigned long);
	np_alin = 0;
	{
		struct np_walk w = np_walk(np_a);

		if (w.ok) {
			unsigned long *ms = (unsigned long *)np_sym("memstart_addr");

			np_a_pa = w.pa;
			if (ms) {
				np_alin = ((w.pa - *ms) | PAGE_OFFSET) & PAGE_MASK;
				np_alin += np_a & ~PAGE_MASK;
			}
		}
	}

	pad_lk = np_callable((unsigned long)np_probe_lookup);
	pad_sys = np_callable((unsigned long)np_probe_syscall);
	pr_info(NP_TAG "stub pads: lookup=%d syscall=%d\n", pad_lk, pad_sys);

	pr_info(NP_TAG "---- entries and guarded bits ----\n");
	np_entry("patch_text", (unsigned long)np_insn_patch_text);
	np_entry("insn_write", (unsigned long)np_insn_write);
	np_entry("set_fixmap", (unsigned long)np_set_fixmap);
	np_entry("nofault_rd ", (unsigned long)copy_from_kernel_nofault);
	np_entry("our lookup ", (unsigned long)np_probe_lookup);
	np_entry("check_unshare", csf);
	np_entry("proc_pid_st", pps);
	np_entry("A ns_lookup", np_a);
	np_entry("B reboot slot", np_b);

	pr_info(NP_TAG "---- page table dump ----\n");
	np_dump("A ns_lookup ", np_a);
	np_dump("B sys_table ", np_b);
	np_dump("C sysctl    ", np_c);
	if (np_alin)
		np_dump("A linear    ", np_alin);
	pr_info(NP_TAG "A pa=0x%lx Alin=%px memstart=%px\n", np_a_pa, (void *)np_alin,
		(void *)np_sym("memstart_addr"));

	/*
	 * run directly, no stop_machine. the cpu stopper threads the kernel
	 * source describes do not exist on this device: not one thread named
	 * stopper/N or migration/N is running, so __stop_cpus queues work nobody
	 * ever services and waits forever. the stubs make the window safe without
	 * it: the value written into the ns lookup slot answers -ENOENT, which is
	 * exactly what a missing entry answers today, and the reboot slot would
	 * answer -ENOSYS, which only matters to a reboot this device is not doing
	 */
	pr_info(NP_TAG "---- phase 2: everything except the engine, run directly ----\n");
	p.a = np_read(np_a);
	p.b = np_read(np_b);
	p.c = np_read(np_c);
	np_phase2_cb(&p);

	/* leave the machine exactly as we found it, and stay if we cannot */
	if (np_restore_failed_a || np_restore_failed_b) {
		pr_err(NP_TAG "a restore failed, this module must stay loaded\n");
		try_module_get(THIS_MODULE);
	}

	/*
	 * the kernel patcher calls stop_machine internally, and stop_machine never
	 * completes on this device: the cpu stopper threads the source describes are
	 * not running, so the work queued for each cpu is never picked up. a first
	 * probe that registered a kprobe already proved the cost of that path once:
	 * the kprobe optimizer hung in stop_machine and every later module load has
	 * been blocked in trace_kprobe_module_callback ever since. off unless asked
	 */
	if (engine) {
		pr_info(NP_TAG "---- phase 1: engine patcher requested, it will not return ----\n");
		np_phase_engine();
	} else {
		pr_info(NP_TAG "engine patcher test skipped: stop_machine never completes on this device (engine=1 to try)\n");
	}
	pr_info(NP_TAG "---- done: A=0x%llx (orig 0x%llx) B=0x%llx (orig 0x%llx) ----\n",
		(unsigned long long)np_ivac_read(np_a), (unsigned long long)p.a,
		(unsigned long long)np_ivac_read(np_b), (unsigned long long)p.b);
	return 0;
}

static void __exit np_exit(void)
{
	pr_info(NP_TAG "unloading\n");
}

module_init(np_init);
module_exit(np_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("dsh");
MODULE_DESCRIPTION("minimal probe: why a rodata store does not land");
/* module name is nsprobe2: a stuck nsprobe from a stop_machine hang is still loading */
