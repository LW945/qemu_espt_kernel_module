#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <asm/pgalloc.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("netlink example");

#define SOFTEPTIO 0xAF

#define SOFTEPT_INIT _IOWR(SOFTEPTIO, 0x1, int)
#define SOFTEPT_SET_ENTRY _IOWR(SOFTEPTIO, 0x2, struct SofteptEntry)
#define SOFTEPT_FLUSH_ENTRY _IOWR(SOFTEPTIO, 0x3, struct SofteptEntry)
#define SOFTEPT_MMIO_ENTRY _IOWR(SOFTEPTIO, 0x4, struct SofteptEntry)
#define SOFTEPT_PRINT_ENTRY _IOWR(SOFTEPTIO, 0x5, struct SofteptEntry)

typedef pgd_t* (*custom_pgd_alloc)(struct mm_struct *mm);
typedef int (*custom_pud_alloc)(struct mm_struct *mm, p4d_t *p4d, unsigned long address);
typedef int (*custom_pmd_alloc)(struct mm_struct *mm, pud_t *pud, unsigned long address);
typedef int (*custom_pte_alloc)(struct mm_struct *mm, pmd_t *pmd);
typedef void (*custom_flush_tlb_all)(void);

custom_pgd_alloc my_pgd_alloc; 
custom_pud_alloc my_pud_alloc; 
custom_pmd_alloc my_pmd_alloc;
custom_pte_alloc my_pte_alloc;
custom_flush_tlb_all my_flush_tlb_all;

pgd_t * gpa_pgd, * hva_pgd, *tmp_pgd;
pud_t * gpa_pud, * hva_pud;
pmd_t * gpa_pmd, * hva_pmd;
pte_t * gpa_pte, * hva_pte, *tmp_pte;

struct task_struct *task;
struct mm_struct *mm;
uint64_t gpa, hva, pa_gpa, pa_hva;
int pid;

struct SofteptEntry{
    union{
        struct{
            uint64_t gpa;
            uintptr_t hva;
        }set_entry;
        struct{
            uint64_t *list;
            int size;
        }flush_entry;
        struct{
            uint64_t gpa;
            uint64_t val;
            int add;
        }mmio_entry;
    };
};
static int softept_dev_open(struct inode *inode, struct file *filp)
{
	printk ("softept open ok\n");
	return 0;
}

static int softept_dev_release(struct inode *inode, struct file *filp)
{
	printk ("softept release ok\n");
	return 0;
}

static int softept_dev_mmap(struct file *file, struct vm_area_struct *vma)
{
	printk ("softept mmap ok\n");
	return 0;
}

static int softept_dev_ioctl_init(int pid_value)
{
	pid = pid_value;
	task = get_pid_task(find_get_pid(pid),PIDTYPE_PID);
	mm = task->mm;
	return 0;
}

static int softept_dev_ioctl_set_entry(struct SofteptEntry softept_entry)
{
	gpa = softept_entry.set_entry.gpa;
	hva = softept_entry.set_entry.hva;

	printk("softept_dev_ioctl_set_entry!, gpa: %llx, hva: %llx\n", gpa, hva);

	hva_pgd = pgd_offset(mm, hva);
	if(!my_pud_alloc(mm, &__p4d(pgd_val(*hva_pgd)), hva)){		
		hva_pud = pud_offset(&__p4d(pgd_val(*hva_pgd)), hva);
		if(!my_pmd_alloc(mm, hva_pud, hva));{
			hva_pmd = pmd_offset(hva_pud, hva);
			if(!my_pte_alloc(mm, hva_pmd)){
				hva_pte = pte_offset_kernel(hva_pmd, hva);
				if(!pte_present(*hva_pte)){
					tmp_pte = (pte_t *)get_zeroed_page(GFP_KERNEL_ACCOUNT);
					set_pte(hva_pte, __pte(_PAGE_TABLE | __pa(tmp_pte)));
				}						
			}			
		}
	}

	gpa_pgd = pgd_offset(mm, gpa);
	if(!my_pud_alloc(mm, &__p4d(pgd_val(*gpa_pgd)), gpa)){
		if(!(pgd_flags(*(gpa_pgd)) & _PAGE_PRESENT)){
			tmp_pgd = (pgd_t *)get_zeroed_page(GFP_KERNEL_ACCOUNT);
			set_pgd(gpa_pgd, __pgd(_PAGE_TABLE | __pa(tmp_pgd)));
		}
		gpa_pud = pud_offset(&__p4d(pgd_val(*gpa_pgd)), gpa);
		if(!my_pmd_alloc(mm, gpa_pud, gpa));{
			gpa_pmd = pmd_offset(gpa_pud, gpa);
			if(!my_pte_alloc(mm, gpa_pmd)){
				gpa_pte = pte_offset_kernel(gpa_pmd, gpa);
				pa_gpa = (pte_pfn(*gpa_pte) << PAGE_SHIFT) | (gpa & ~PAGE_MASK);
				pa_hva = (pte_pfn(*hva_pte) << PAGE_SHIFT) | (hva & ~PAGE_MASK);
				printk("hva_value: %llx\n", *(uint64_t *)__va(pa_hva));	
				set_pte(gpa_pte, *hva_pte);
			}			
		}
	}

	my_flush_tlb_all();
	return 0;
}

static int softept_dev_ioctl_flush_entry(struct SofteptEntry softept_entry)
{
	int i;
	int len = softept_entry.flush_entry.size;
	unsigned int *list = kmalloc(len * sizeof(uint64_t), GFP_KERNEL);

	printk("softept_dev_ioctl_flush_entry!, len: %d\n", len);

	if (copy_from_user(list, (void *)softept_entry.flush_entry.list, softept_entry.flush_entry.size * sizeof(uint64_t))){
		kfree(list);
		return 0;
	}

	for(i = 0; i < len; i++){
		gpa = list[i];
		printk("gpa: %llx\n", gpa);
		gpa_pgd = pgd_offset(mm, gpa);
		if(!my_pud_alloc(mm, &__p4d(pgd_val(*gpa_pgd)), gpa)){
			printk("pud \n");
			if(!(pgd_flags(*(gpa_pgd)) & _PAGE_PRESENT)){
				printk("pgd \n");
				tmp_pgd = (pgd_t *)get_zeroed_page(GFP_KERNEL_ACCOUNT);
				set_pgd(gpa_pgd, __pgd(_PAGE_TABLE | __pa(tmp_pgd)));
			}
			gpa_pud = pud_offset(&__p4d(pgd_val(*gpa_pgd)), gpa);
			if(!my_pmd_alloc(mm, gpa_pud, gpa)){
				printk("pmd \n");
				gpa_pmd = pmd_offset(gpa_pud, gpa);
				if(!my_pte_alloc(mm, gpa_pmd)){
					printk("pte \n");
					gpa_pte = pte_offset_kernel(gpa_pmd, gpa);	
					set_pte(gpa_pte, __pte(0));
					printk("pte: %llx\n", gpa_pte->pte);
				}			
			}
		}
	}

	my_flush_tlb_all();
	return 0;
}

static int softept_dev_ioctl_mmio_entry(struct SofteptEntry softept_entry)
{
	int add = softept_entry.mmio_entry.add;
	uint64_t value = softept_entry.mmio_entry.val;
	gpa = softept_entry.mmio_entry.gpa;

	printk("softept_dev_ioctl_mmio_entry!, add: %d, value: %llx, gpa: %llx\n", add, value, gpa);

	gpa_pgd = pgd_offset(mm, gpa);
	if(!my_pud_alloc(mm, &__p4d(pgd_val(*gpa_pgd)), gpa)){
		if(!(pgd_flags(*(gpa_pgd)) & _PAGE_PRESENT)){
			tmp_pgd = (pgd_t *)get_zeroed_page(GFP_KERNEL_ACCOUNT);
			set_pgd(gpa_pgd, __pgd(_PAGE_TABLE | __pa(tmp_pgd)));
		}
		gpa_pud = pud_offset(&__p4d(pgd_val(*gpa_pgd)), gpa);
		if(!my_pmd_alloc(mm, gpa_pud, gpa));{
			gpa_pmd = pmd_offset(gpa_pud, gpa);
			if(!my_pte_alloc(mm, gpa_pmd)){
				gpa_pte = pte_offset_kernel(gpa_pmd, gpa);
				if(add){
					tmp_pte = (pte_t *)get_zeroed_page(GFP_KERNEL_ACCOUNT);
					set_pte(gpa_pte, __pte(_PAGE_TABLE | __pa(tmp_pte)));
					*(uint64_t *)tmp_pte = value;	
				}
				else{
					set_pte(gpa_pte, __pte(0));					
				}
			}			
		}
	}

	my_flush_tlb_all();
	return 0;
}

static int softept_dev_ioctl_print_entry(struct SofteptEntry softept_entry)
{
	gpa = softept_entry.mmio_entry.gpa;

	printk("softept_dev_ioctl_print_entry!, gpa: %llx\n", gpa);

	gpa_pgd = pgd_offset(mm, gpa);
	if(!my_pud_alloc(mm, &__p4d(pgd_val(*gpa_pgd)), gpa)){
			printk("pud \n");
			if(!(pgd_flags(*(gpa_pgd)) & _PAGE_PRESENT)){
				printk("pgd \n");
				tmp_pgd = (pgd_t *)get_zeroed_page(GFP_KERNEL_ACCOUNT);
				set_pgd(gpa_pgd, __pgd(_PAGE_TABLE | __pa(tmp_pgd)));
			}
			gpa_pud = pud_offset(&__p4d(pgd_val(*gpa_pgd)), gpa);
			if(!my_pmd_alloc(mm, gpa_pud, gpa)){
				printk("pmd \n");
				gpa_pmd = pmd_offset(gpa_pud, gpa);
				if(!my_pte_alloc(mm, gpa_pmd)){
					printk("pte \n");
					gpa_pte = pte_offset_kernel(gpa_pmd, gpa);	
					printk("pte: %llx\n", gpa_pte->pte);
				}			
			}
		}
	return 0;
}

static long softept_dev_ioctl(struct file *filp,
			  unsigned int ioctl, unsigned long arg)
{
	printk("softept_dev_ioctl! %u\n", ioctl);
	int r;
    r = -EINVAL;

	switch (ioctl) {
	case SOFTEPT_INIT:{
		int pid_value;	
		r = -EFAULT;
		if (copy_from_user(&pid_value, (void *)arg, sizeof(int)))
			goto out;
		r = softept_dev_ioctl_init(pid_value);
		if(r)
			goto out;
		break;
	}
	case SOFTEPT_SET_ENTRY:{
		struct SofteptEntry softept_set_entry;
		r = -EFAULT;
		if (copy_from_user(&softept_set_entry, (void *)arg, sizeof(struct SofteptEntry)))
			goto out;
		r = softept_dev_ioctl_set_entry(softept_set_entry);
		if(r)
			goto out;
		break;
	}
	case SOFTEPT_FLUSH_ENTRY:{
		struct SofteptEntry softept_flush_entry;
		r = -EFAULT;
		if (copy_from_user(&softept_flush_entry, (void *)arg, sizeof(struct SofteptEntry)))
			goto out;
		printk("# %lx\n", softept_flush_entry.flush_entry.list);
		r = softept_dev_ioctl_flush_entry(softept_flush_entry);
		if(r)
			goto out;
		break;
	}
	case SOFTEPT_MMIO_ENTRY:{
		struct SofteptEntry softept_mmio_entry;
		r = -EFAULT;
		if (copy_from_user(&softept_mmio_entry, (void *)arg, sizeof(struct SofteptEntry)))
			goto out;
		r = softept_dev_ioctl_mmio_entry(softept_mmio_entry);
		break;
	}
	case SOFTEPT_PRINT_ENTRY:{
		struct SofteptEntry softept_print_entry;
		r = -EFAULT;
		if (copy_from_user(&softept_print_entry, (void *)arg, sizeof(struct SofteptEntry)))
			goto out;
		r = softept_dev_ioctl_print_entry(softept_print_entry);
		break;
	}
	default:
		;
	}
out:
	return r;
}

static struct file_operations softept_chardev_ops = {
	.open		    = softept_dev_open,
	.release        = softept_dev_release,
	.unlocked_ioctl = softept_dev_ioctl,
	.compat_ioctl   = softept_dev_ioctl,
	.mmap			= softept_dev_mmap
};

static struct miscdevice softept_dev = {
	MISC_DYNAMIC_MINOR,
	"softept",
	&softept_chardev_ops,
};

int softept_init(void)
{
	int r;
	r = misc_register(&softept_dev);
	if (r) {
		printk (KERN_ERR "softept: misc device register failed\n");
	}    

	my_pgd_alloc = (custom_pgd_alloc)kallsyms_lookup_name("pgd_alloc");
	my_pud_alloc = (custom_pud_alloc)kallsyms_lookup_name("__pud_alloc");
	my_pmd_alloc = (custom_pmd_alloc)kallsyms_lookup_name("__pmd_alloc");
	my_pte_alloc = (custom_pte_alloc)kallsyms_lookup_name("__pte_alloc");
	my_flush_tlb_all = (custom_flush_tlb_all)kallsyms_lookup_name("flush_tlb_all");

	printk("softept_init ok\n");
    return 0;
}

void softept_exit(void)
{
	misc_deregister(&softept_dev);
    printk("softept_exit ok\n");
}

module_init(softept_init);
module_exit(softept_exit);
