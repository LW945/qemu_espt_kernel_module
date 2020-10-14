#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/file.h>
#include <asm/pgalloc.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("netlink example");

#define ESPT_SET_ENTRY 0
#define ESPT_FLUSH_ENTRY 1

typedef pgd_t* (*custom_pgd_alloc)(struct mm_struct *mm);
typedef int (*custom_pud_alloc)(struct mm_struct *mm, p4d_t *p4d, unsigned long address);
typedef int (*custom_pmd_alloc)(struct mm_struct *mm, pud_t *pud, unsigned long address);
typedef int (*custom_pte_alloc)(struct mm_struct *mm, pmd_t *pmd);

struct ESPTEntry{
	union{
		struct{
			uint64_t gva;
			uintptr_t hva;
			int pid;
		}set_entry;
		struct{
			uint64_t *list;
			int size;
			int pid;
		}flush_entry;
	};
};

static int espt_dev_open(struct inode *inode, struct file *filp)
{
	printk ("espt open ok\n");
	return 0;
}

static int espt_dev_release(struct inode *inode, struct file *filp)
{
	printk ("espt release ok\n");
	return 0;
}

static int espt_dev_mmap(struct file *file, struct vm_area_struct *vma)
{
	printk ("espt mmap ok\n");
	return 0;
}

static int espt_dev_ioctl_set_entry(struct ESPTEntry espt_entry)
{
	struct task_struct *task;
	struct mm_struct *mm;
	uint64_t pa_gva, pa_hva;
	uint64_t gva = espt_entry.set_entry.gva;
	uint64_t hva = espt_entry.set_entry.hva;
	int pid = espt_entry.set_entry.pid;
	
	pgd_t * gva_pgd, * hva_pgd;
	pud_t * gva_pud, * hva_pud;
	pmd_t * gva_pmd, * hva_pmd;
	pte_t * gva_pte, * hva_pte;

	custom_pgd_alloc my_pgd_alloc;
	custom_pud_alloc my_pud_alloc;
	custom_pmd_alloc my_pmd_alloc;
	custom_pte_alloc my_pte_alloc;

	my_pgd_alloc = (custom_pgd_alloc)kallsyms_lookup_name("pgd_alloc");
	my_pud_alloc = (custom_pud_alloc)kallsyms_lookup_name("__pud_alloc");
	my_pmd_alloc = (custom_pmd_alloc)kallsyms_lookup_name("__pmd_alloc");
	my_pte_alloc = (custom_pte_alloc)kallsyms_lookup_name("__pte_alloc");

	task = get_pid_task(find_get_pid(pid),PIDTYPE_PID);
	mm = task->mm;

	hva_pgd = pgd_offset(mm, hva);
	if(!my_pud_alloc(mm, &__p4d(pgd_val(*hva_pgd)), hva)){		
		hva_pud = pud_offset(&__p4d(pgd_val(*hva_pgd)), hva);
		if(!my_pmd_alloc(mm, hva_pud, hva));{
			hva_pmd = pmd_offset(hva_pud, hva);
			if(!my_pte_alloc(mm, hva_pmd)){
				hva_pte = pte_offset_kernel(hva_pmd, hva);
				if(!pte_present(*hva_pte)){
					pte_t * tmp = (pte_t *)get_zeroed_page(GFP_KERNEL_ACCOUNT);
					set_pte(hva_pte, __pte(_PAGE_TABLE | __pa(tmp)));
				}						
			}			
		}
	}

	gva_pgd = pgd_offset(mm, gva);
	if(!my_pud_alloc(mm, &__p4d(pgd_val(*gva_pgd)), gva)){
		if(!(pgd_flags(*(gva_pgd)) & _PAGE_PRESENT)){
			pgd_t * tmp = (pgd_t *)get_zeroed_page(GFP_KERNEL_ACCOUNT);
			set_pgd(gva_pgd, __pgd(_PAGE_TABLE | __pa(tmp)));
		}
		gva_pud = pud_offset(&__p4d(pgd_val(*gva_pgd)), gva);
		if(!my_pmd_alloc(mm, gva_pud, gva));{
			gva_pmd = pmd_offset(gva_pud, gva);
			if(!my_pte_alloc(mm, gva_pmd)){
				gva_pte = pte_offset_kernel(gva_pmd, gva);
				pa_gva = (pte_pfn(*gva_pte) << PAGE_SHIFT) | (gva & ~PAGE_MASK);
				pa_hva = (pte_pfn(*hva_pte) << PAGE_SHIFT) | (hva & ~PAGE_MASK);	
				if(pa_gva != pa_hva){
					set_pte(gva_pte, *hva_pte);
				}
			}			
		}
	}
	return 0;
}

static int espt_dev_ioctl_flush_entry(struct ESPTEntry espt_entry)
{
	struct task_struct *task;
	struct mm_struct *mm;
	uint64_t gva;
	int i;

	int len = espt_entry.flush_entry.size;
	int pid = espt_entry.flush_entry.size;
	uint64_t *list = espt_entry.flush_entry.list;

	pgd_t * gva_pgd;
	pud_t * gva_pud;
	pmd_t * gva_pmd;
	pte_t * gva_pte;

	custom_pgd_alloc my_pgd_alloc;
	custom_pud_alloc my_pud_alloc;
	custom_pmd_alloc my_pmd_alloc;
	custom_pte_alloc my_pte_alloc;

	my_pgd_alloc = (custom_pgd_alloc)kallsyms_lookup_name("pgd_alloc");
	my_pud_alloc = (custom_pud_alloc)kallsyms_lookup_name("__pud_alloc");
	my_pmd_alloc = (custom_pmd_alloc)kallsyms_lookup_name("__pmd_alloc");
	my_pte_alloc = (custom_pte_alloc)kallsyms_lookup_name("__pte_alloc");

	task = get_pid_task(find_get_pid(pid),PIDTYPE_PID);
	mm = task->mm;
	for(i = 0; i < len; i++){
		gva = list[i];
		gva_pgd = pgd_offset(mm, gva);
		if(!my_pud_alloc(mm, &__p4d(pgd_val(*gva_pgd)), gva)){
			if(!(pgd_flags(*(gva_pgd)) & _PAGE_PRESENT)){
				pgd_t * tmp = (pgd_t *)get_zeroed_page(GFP_KERNEL_ACCOUNT);
				set_pgd(gva_pgd, __pgd(_PAGE_TABLE | __pa(tmp)));
			}
			gva_pud = pud_offset(&__p4d(pgd_val(*gva_pgd)), gva);
			if(!my_pmd_alloc(mm, gva_pud, gva));{
				gva_pmd = pmd_offset(gva_pud, gva);
				if(!my_pte_alloc(mm, gva_pmd)){
					gva_pte = pte_offset_kernel(gva_pmd, gva);	
					set_pte(gva_pte, __pte(0));
				}			
			}
		}
	}
	return 0;
}

static long espt_dev_ioctl(struct file *filp,
			  unsigned int ioctl, unsigned long arg)
{
	int r = -EINVAL;

	switch (ioctl) {
	case ESPT_SET_ENTRY:{
		struct ESPTEntry espt_set_entry;
		r = -EFAULT;
			if (copy_from_user(&espt_set_entry, (void *)arg, sizeof(struct ESPTEntry)))
				goto out;
			r = espt_dev_ioctl_set_entry(espt_set_entry);
			if(r)
				goto out;
			break;
	}
	case ESPT_FLUSH_ENTRY:{
		struct ESPTEntry espt_flush_entry;
		uint64_t *addr_list;
		r = -EFAULT;
			if (copy_from_user(&espt_flush_entry, (void *)arg, sizeof(struct ESPTEntry)))
				goto out;
			if (copy_from_user(addr_list, espt_flush_entry.flush_entry.list, espt_flush_entry.flush_entry.size * sizeof(uint64_t)))
				goto out;
			r = espt_dev_ioctl_flush_entry(espt_flush_entry);
			if(r)
				goto out;
			break;
	}
	default:
		;
	}
out:
	return r;
}

static struct file_operations espt_chardev_ops = {
	.open		= espt_dev_open,
	.release        = espt_dev_release,
	.unlocked_ioctl = espt_dev_ioctl,
	.compat_ioctl   = espt_dev_ioctl,
	.mmap			= espt_dev_mmap
};

static struct miscdevice espt_dev = {
	MISC_DYNAMIC_MINOR,
	"espt",
	&espt_chardev_ops,
};

int espt_init(void)
{
	int r;
	r = misc_register(&espt_dev);
	if (r) {
		printk (KERN_ERR "espt: misc device register failed\n");
	}    
	printk("espt_init ok\n");
    return 0;
}

void espt_exit(void)
{
	misc_deregister(&espt_dev);
    printk("espt_exit ok\n");
}

module_init(espt_init);
module_exit(espt_exit);
