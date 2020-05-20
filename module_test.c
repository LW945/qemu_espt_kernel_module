#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <asm/tlbflush.h>
#include <asm/pgalloc.h>
#include <linux/export.h>
#include <net/sock.h>
#include <linux/netlink.h>

#define NETLINK_TEST     30
#define MSG_LEN            125
#define USER_PORT        100

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("netlink example");

typedef pgd_t* (*custom_pgd_alloc)(struct mm_struct *mm);
typedef int (*custom_pud_alloc)(struct mm_struct *mm, p4d_t *p4d, unsigned long address);
typedef int (*custom_pmd_alloc)(struct mm_struct *mm, pud_t *pud, unsigned long address);
typedef int (*custom_pte_alloc)(struct mm_struct *mm, pmd_t *pmd);
typedef void (*custom_flush_tlb_all)(void);

struct sock *nlsk = NULL;
extern struct net init_net;

int send_usrmsg(int *pbuf, uint16_t len)
{
    struct sk_buff *nl_skb;
    struct nlmsghdr *nlh;

    int ret;

    /* 创建sk_buff 空间 */
    nl_skb = nlmsg_new(len, GFP_ATOMIC);
    if(!nl_skb)
    {
        printk("netlink alloc failure\n");
        return -1;
    }

    /* 设置netlink消息头部 */
    nlh = nlmsg_put(nl_skb, 0, 0, NETLINK_TEST, len, 0);
    if(nlh == NULL)
    {
        printk("nlmsg_put failaure \n");
        nlmsg_free(nl_skb);
        return -1;
    }

    /* 拷贝数据发送 */
    memcpy(nlmsg_data(nlh), pbuf, len);
    ret = netlink_unicast(nlsk, nl_skb, USER_PORT, MSG_DONTWAIT);

    return ret;
}

int gva2hpa(unsigned long gva, unsigned long hva, int pid){
	struct task_struct *task;
	struct mm_struct *mm;
	unsigned long pa_gva, pa_hva, pa;
	
	pgd_t * gva_pgd, * hva_pgd;
	pud_t * gva_pud, * hva_pud;
	pmd_t * gva_pmd, * hva_pmd;
	pte_t * gva_pte, * hva_pte;

	custom_pgd_alloc my_pgd_alloc;
	custom_pud_alloc my_pud_alloc;
	custom_pmd_alloc my_pmd_alloc;
	custom_pte_alloc my_pte_alloc;
	custom_flush_tlb_all my_flush_tlb_all;

	my_pgd_alloc = (custom_pgd_alloc)kallsyms_lookup_name("pgd_alloc");
	my_pud_alloc = (custom_pud_alloc)kallsyms_lookup_name("__pud_alloc");
	my_pmd_alloc = (custom_pmd_alloc)kallsyms_lookup_name("__pmd_alloc");
	my_pte_alloc = (custom_pte_alloc)kallsyms_lookup_name("__pte_alloc");
	my_flush_tlb_all = (custom_flush_tlb_all)kallsyms_lookup_name("flush_tlb_all");

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
					printk("PTE Not Present !\n");
					pte_t * tmp = (pte_t *)get_zeroed_page(GFP_KERNEL_ACCOUNT);
					set_pte(hva_pte, __pte(_PAGE_TABLE | __pa(tmp)));
				}
				//printk("HVA PGD Good: %lx\n", pgd_val(*hva_pgd));
				//printk("HVA PUD Good: %lx\n", pud_val(*hva_pud));
				//printk("HVA PMD Good: %lx\n", pmd_val(*hva_pmd));
				printk("HVA PTE Good: %lx\n", pte_val(*hva_pte));						
			}			
		}
	}

	gva_pgd = pgd_offset(mm, gva);
	if(!my_pud_alloc(mm, &__p4d(pgd_val(*gva_pgd)), gva)){
		if(!(pgd_flags(*(gva_pgd)) & _PAGE_PRESENT)){
			printk("pgd Not Present !\n");
			printk("GVA PGD Good: %lx\n", pgd_val(*gva_pgd));
			pgd_t * tmp = (pgd_t *)get_zeroed_page(GFP_KERNEL_ACCOUNT);
			set_pgd(gva_pgd, __pgd(_PAGE_TABLE | __pa(tmp)));
		}
		gva_pud = pud_offset(&__p4d(pgd_val(*gva_pgd)), gva);
		if(!my_pmd_alloc(mm, gva_pud, gva));{
			gva_pmd = pmd_offset(gva_pud, gva);
			if(!my_pte_alloc(mm, gva_pmd)){
				gva_pte = pte_offset_kernel(gva_pmd, gva);
				//printk("CR3 Good: %lx\n", pgd_val(*(mm->pgd)));
				//printk("GVA PGD Good: %lx\n", pgd_val(*gva_pgd));
				//printk("GVA PUD Good: %lx\n", pud_val(*gva_pud));
				//printk("GVA PMD Good: %lx\n", pmd_val(*gva_pmd));
				printk("GVA PTE Good: %lx\n", pte_val(*gva_pte));
				pa_gva = (pte_pfn(*gva_pte) << PAGE_SHIFT) | (gva & ~PAGE_MASK);
				pa_hva = (pte_pfn(*hva_pte) << PAGE_SHIFT) | (hva & ~PAGE_MASK);	
				if(pa_gva != pa_hva){
					set_pte(gva_pte, *hva_pte);
					//printk("GVA Address: %lx\n", pa_gva);
					//printk("HVA Address: %lx\n", pa_hva);	
					smp_wmb();
				}
			}			
		}
	}
	my_flush_tlb_all();
	return 1;
}

static void netlink_rcv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = NULL;
    int pid, result = 0;
	unsigned long gva = 0xFFFFFFFFFFFF, hva = 0xFFFFFFFFFFFF;

    if(skb->len >= nlmsg_total_size(0))
    {
        nlh = nlmsg_hdr(skb);
        gva = *(unsigned long *)NLMSG_DATA(nlh);
		hva = *(unsigned long *)(NLMSG_DATA(nlh) + sizeof(unsigned long));
		pid = *(int *)(NLMSG_DATA(nlh) + 2 * sizeof(unsigned long));
		if(gva != 0xFFFFFFFFFFFF && hva != 0xFFFFFFFFFFFF){
		    printk("kernel recv gva from user: %0lx\n", gva);
			printk("kernel recv hva from user: %0lx\n", hva);
			printk("kernel recv pid from user: %d\n", pid);
			result = gva2hpa(gva, hva, pid);
		    send_usrmsg(&result, sizeof(result));
		}
    }
}

struct netlink_kernel_cfg cfg = { 
        .input  = netlink_rcv_msg, /* set recv callback */
};  

int test_netlink_init(void)
{
    /* create netlink socket */
    nlsk = (struct sock *)netlink_kernel_create(&init_net, NETLINK_TEST, &cfg);
    if(nlsk == NULL)
    {   
        printk("netlink_kernel_create error !\n");
        return -1; 
    }   
    printk("test_netlink_init\n");
    
    return 0;
}

void test_netlink_exit(void)
{
    if (nlsk){
        netlink_kernel_release(nlsk); /* release ..*/
        nlsk = NULL;
    }   
    printk("test_netlink_exit!\n");
}

module_init(test_netlink_init);
module_exit(test_netlink_exit);
