// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

/*
 * one place that decides how this module hooks things. the knobs below are the
 * whole policy: whether inline hooks run at all, which write path the engine
 * uses, and whether the engine may open a fixmap slot of its own. anything that
 * changes how we hook belongs here rather than at a call site
 */
#include <asm/barrier.h>
#include <asm/pgtable-hwdef.h>
#include <asm/tlbflush.h>

#include "ds.h"
#include "hk_patch.h"

bool droid_lkm_inline_hooks_on;

static bool droid_lkm_inline_hook = true;
module_param_named(inline_hook, droid_lkm_inline_hook, bool, 0444);
MODULE_PARM_DESC(inline_hook, "install inline hooks, on by default");

/*
 * 0 keeps the engine on the kernel's own patch primitive, which owns the fixmap
 * slot, the frame and the locking. 1 hands the engine our own fixmap writer:
 * that store goes through an alias this module computes from its build headers,
 * and on the MTK device every engine write then faulted in hk_patch_slot_cb.
 * only pick 1 to reproduce that, never in production
 */
static uint droid_lkm_write_path;
module_param_named(write_path, droid_lkm_write_path, uint, 0444);
MODULE_PARM_DESC(write_path, "0 kernel patch primitive (default), 1 the module's own fixmap writer");


int droid_lkm_do_inline_hook(struct hk_inline *h, const char *sym,
			     const char *wrap)
{
	if (!droid_lkm_inline_hooks_on) {
		pr_warn_once("[droid_lkm] inline hooks are off (inline_hook=0), %s not hooked\n", sym);
		return -EOPNOTSUPP;
	}
	return hk_inline_hook(h, sym, wrap);
}

void droid_lkm_hook_policy_apply(void)
{
	droid_lkm_inline_hooks_on = droid_lkm_inline_hook;
	hk_patch_set_write(droid_lkm_write_path ? hk_write_fixmap : NULL);
	droid_lkm_info("hook policy: inline_hook=%d write_path=%u\n",
		       droid_lkm_inline_hooks_on, droid_lkm_write_path);
}

// every install lands here so the report can name the ones that failed
#define DROID_LKM_HOOK_RECORDS		8

static struct {
	const char *sym;
	bool installed;
	int err;
	/*
	 * hk_inline.use_br_x17: true when the engine had to clear the pte guarded
	 * bit and jump back through br x17 so the resume lands mid function. that
	 * is the one shape a BTI kernel can refuse, so it is reported rather than
	 * left to be discovered by a faulting reader later. the library clears the
	 * bit, flushes the tlb and re-reads the entry before it reports success, so
	 * installed && guarded means the landing pad was verified, not assumed.
	 */
	bool guarded;
} droid_lkm_hook_records[DROID_LKM_HOOK_RECORDS];
static unsigned int droid_lkm_hook_record_count;

// container critical hooks refuse the load
// the rest refuse their own feature
static bool droid_lkm_hook_critical_missing;

static bool droid_lkm_degrade;
module_param_named(degrade, droid_lkm_degrade, bool, 0444);
MODULE_PARM_DESC(degrade,
	"1 keeps running when a container critical hook cannot install, 0 refuses the load");

int droid_lkm_hook_install_critical(struct hk_inline *h, const char *sym,
				    const char *wrap)
{
	int ret = droid_lkm_hook_install(h, sym, wrap);

	if (ret)
		droid_lkm_hook_critical_missing = true;

	return ret;
}

bool droid_lkm_hook_critical_ok(void)
{
	return !droid_lkm_hook_critical_missing;
}

bool droid_lkm_degrade_enabled(void)
{
	return droid_lkm_degrade;
}

/*
 * the one inline hook shape a bti kernel can refuse. when the resume has to
 * land in the middle of the hooked function the engine clears the guarded bit
 * on that page and jumps back through br x17 rather than ret x17. the bit is
 * part of the translation, so the entry write alone leaves every cpu that
 * already translated the page on the guarded copy, and the next entry into the
 * function raises a bti exception, which is fatal.
 *
 * hk_inline exposes the pages the engine touched, so this is checkable without
 * executing the hooked function: confirm the bit is gone from the entry, flush
 * the page again so no cpu keeps the old translation, and read it back. a hook
 * that took no guarded page returns immediately, so the common shape pays
 * nothing for this.
 */
static bool droid_lkm_guard_settle(struct hk_inline *h)
{
	u32 i;

	if (!h->use_br_x17)
		return true;

	for (i = 0; i < h->guard_count && i < HK_INLINE_GUARD_MAX; i++) {
		struct hk_inline_guard *g = &h->guard[i];

		if (!g->active || !g->had_gp)
			continue;
		if (!g->ptep)
			return false;

		if (READ_ONCE(*g->ptep) & PTE_GP)
			WRITE_ONCE(*g->ptep, g->pte & ~PTE_GP);

		/* the entry is not the translation a cpu is already holding */
		__flush_tlb_kernel_pgtable(g->page);
		dsb(ish);
		isb();

		if (READ_ONCE(*g->ptep) & PTE_GP)
			return false;
	}

	return true;
}

int droid_lkm_hook_install(struct hk_inline *h, const char *sym,
			   const char *wrap)
{
	unsigned int i;
	int ret = droid_lkm_do_inline_hook(h, sym, wrap);

	/*
	 * a hook that installed but left a guarded page behind passes every other
	 * check and then faults on the first entry into the function, from a reader
	 * that has nothing to do with this module. take it back out instead of
	 * shipping a trap, the caller already treats a failed hook as a lost feature
	 */
	if (!ret && !droid_lkm_guard_settle(h)) {
		droid_lkm_err("hook: %s left a bti guarded page behind, rolling it back (the branch back would fault)\n",
			       sym);
		hk_inline_disable(h);
		h->orig = 0;
		ret = -EFAULT;
	}

	for (i = 0; i < droid_lkm_hook_record_count; i++) {
		if (droid_lkm_hook_records[i].sym == sym)
			break;
	}
	if (i == droid_lkm_hook_record_count) {
		if (droid_lkm_hook_record_count == DROID_LKM_HOOK_RECORDS)
			return ret;
		droid_lkm_hook_record_count++;
	}

	droid_lkm_hook_records[i].sym = sym;
	droid_lkm_hook_records[i].installed = !ret && h->orig;
	droid_lkm_hook_records[i].err = ret;
	droid_lkm_hook_records[i].guarded = h->use_br_x17;

	return ret;
}

void droid_lkm_hook_report(void)
{
	unsigned int i, installed = 0;

	for (i = 0; i < droid_lkm_hook_record_count; i++) {
		if (droid_lkm_hook_records[i].installed)
			installed++;
		droid_lkm_info("hook: %s %s (%d) br_x17=%d\n",
			       droid_lkm_hook_records[i].sym,
			       droid_lkm_hook_records[i].installed ?
			       "installed" : "NOT installed",
			       droid_lkm_hook_records[i].err,
			       droid_lkm_hook_records[i].guarded);
	}
	droid_lkm_info("hooks: inline=%d %u/%u installed\n",
		       droid_lkm_inline_hooks_on, installed,
		       droid_lkm_hook_record_count);
}
