#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <asm/tlbflush.h>
#include <linux/kup.h>

struct saved_pfns spfn = {
	.lock = __SPIN_LOCK_UNLOCKED(spfn.lock),
	.ppfns = LIST_HEAD_INIT(spfn.ppfns),
	.pagesexist = false,
};

static struct task_struct *find_task_struct(int pid)
{
	struct task_struct *task;
	for_each_process(task) {
		if (task->pid == pid)
			return task;
	}
	return NULL;
}

asmlinkage long sys_preserve(int pid, const void __user *pinfo, size_t count)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct page *page;
	struct pidpfns *ppfns;
	unsigned long i, j;
	unsigned long pfn;

	task = find_task_struct(pid);
	if (task == NULL)
		return -EINVAL;
	mm = task->mm;

	ppfns = kmalloc(sizeof(*ppfns), GFP_KERNEL);
	if (ppfns == NULL)
		return -ENOMEM;

	/* changing the page flags for all of the pages */
	down_read(&mm->mmap_sem);

	kup_log("recieved count value: %ld\n", count);
	ppfns->size = count * sizeof(struct pfn_info);
	ppfns->pinfo = vmalloc(ppfns->size);
	if (ppfns->pinfo == NULL)
		return -ENOMEM;
	if (unlikely(copy_from_user(ppfns->pinfo, pinfo, ppfns->size)))
		return -EFAULT;
	for (i = 0; i < count; i++) {
		for (j = 0; j < ppfns->pinfo[i].len; j++) {
			pfn = ppfns->pinfo[i].pfn + j;
			page = pfn_to_page(pfn);
			mark_page_reserved(page);
			SetPageUnevictable(page);
		}
		kup_dbg_pfn_info(KUP_DEBUG_MID, &ppfns->pinfo[i]);
	}

	up_read(&mm->mmap_sem);

	/* add this to the main list --> saved_pfns */
	spfn.pagesexist = true;
	list_add(&ppfns->proclist, &spfn.ppfns);
	return 0;
}

asmlinkage long sys_prestore(const void __user *pinfo, size_t len)
{
	struct task_struct *task = current;
	struct mm_struct *mm = task->mm;
	struct pfn_info *savedpfns;

	/* alloc, copy, init */
    kup_log("len: %lu\n", len);
	savedpfns = vmalloc(len);
	if (!savedpfns)
		return -ENOMEM;
	if (unlikely(copy_from_user(savedpfns, pinfo, len)))
		return -EFAULT;
	mm->savedpfns = savedpfns;
	mm->pfncount = len/sizeof(struct pfn_info);

	/* and, finally, print out log */
	kup_log("len: %lu, num. of pfn_info: %lu\n", len, mm->pfncount);
	{
		unsigned long index;
		for (index = 0; index < mm->pfncount; index++)
			kup_dbg_pfn_info(KUP_DEBUG_MID, &mm->savedpfns[index]);
	}
	kup_log("added pfns to the list\n");
	return 0;
}

#if KUP_DEBUG_LEVEL >= KUP_DEBUG_HIGH
static struct page *walk_page_table(struct mm_struct *mm, unsigned long addr)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte;

	struct page *page = NULL;

	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		goto page_out;

	pud = pud_offset(pgd, addr);
	if (pud_none(*pud) || pud_bad(*pud))
		goto page_out;

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		goto page_out;

	ptep = pte_offset_map(pmd, addr);
	if (!ptep)
		goto page_out;
	pte = *ptep;

	page = pte_page(pte);

	pte_unmap(ptep);

page_out:
	return page;

}
#endif

asmlinkage long sys_printvmas(int pid)
{
	struct task_struct *task = current;
	struct mm_struct *mm = task->mm;
	struct vm_area_struct *vma;
	unsigned long num_page;

	down_read(&mm->mmap_sem);
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		num_page = (vma->vm_end - vma->vm_start) / PAGE_SIZE;
		kup_log("vma: (%lx, %lx, %lu)\n",
			vma->vm_start, vma->vm_end, num_page);
		if (vma->vm_flags & VM_DONTDUMP)
			continue;
#if KUP_DEBUG_LEVEL >= KUP_DEBUG_HIGH
		for (addr = vma->vm_start; addr < vma->vm_end; addr += PAGE_SIZE) {
			page = walk_page_table(mm, addr);
			if (page)
				kup_log("addr[%lx]: %lx\n", addr, page_to_pfn(page));
			else
				kup_log("addr[%lx]: -1\n", addr);
		}
#endif
	}
	up_read(&mm->mmap_sem);
	return 0;
}
