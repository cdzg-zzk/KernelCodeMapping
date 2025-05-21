#include <linux/init.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <asm/pgtable.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/hugetlb.h>
#include <asm/pgtable_types.h>
#include <asm/tlbflush.h>
#include <linux/kallsyms.h>

#include <linux/types.h>
#include <net/sock.h>
#include <linux/netlink.h>

#define NETLINK_TEST 17
#define BUF_SIZE (1*PAGE_SIZE)

#define PFN_CHANGE_MASK 0xFFF0000000000FFF

#define FUN_SIZE 100
#define FUN_OFFSET 0x0

static int count = 0;
static void *kbuff;

typedef struct {
    unsigned long addr;
} user_request_t;

typedef struct {
    int response;
} kernel_response_t;

struct {
    __u32 pid;
} user_process;

static struct sock* netlinkfd = NULL;


extern int extern_test_fun(int a, int b);

static noinline int test_fun(int base);
static noinline int test_fun2(int x);
static noinline int test_fun3(int x);

static noinline int test_fun(int base)
{
    int val1 = test_fun2(base);
    int val2 = test_fun3(base + 1);
    int ret = 0;
    if (val1 > val2) {
        ret = val1 - val2;
    } else {
        ret = val2 - val1;
    }
    // return extern_test_fun(base, ret);
    return ret;
}

static noinline int test_fun2(int x)
{
    volatile int result = 0;
    int i = 0;

    while (i < x) {
        result += (x + i) * 2;
        i++;
    }
    return result;
}

static noinline int test_fun3(int x)
{
    volatile int result = 0;
    int i = 0;
    while (i < x) {
        result += i*i + x;
        i++;
    }
    return result;
}
int pmd_huge(pmd_t pmd)
{
    return !pmd_none(pmd) && 
            (pmd_val(pmd) & (_PAGE_PRESENT|_PAGE_PSE)) != _PAGE_PRESENT;
}
// int get_page_table(unsigned long addr)
// {
//     // test_fun(15);
//     printk(KERN_INFO "START_%d\n", count);
//     count++;
//     pgd_t *pgd;
//     p4d_t *p4d;
//     pud_t *pud;
//     pmd_t *pmd;
//     pte_t *pte;
//     struct mm_struct *mm = current->mm;
//     printk(KERN_INFO "current->pid is %d\n", current->pid);   // 检查PGD是否一致，虽然一致，但是还挺重要的
//     if(!mm) {
//         printk(KERN_ERR "No mm_struct for current process\n");
//         return 1;
//     }
//     pgd = pgd_offset(mm, addr);
//     if(pgd_none(*pgd) || pgd_bad(*pgd)) {
//         printk(KERN_INFO "PGD invalid or not present for address 0x%lx\n", addr);
//          return 2;
//     }
//     printk(KERN_INFO "PGD found at %px, value: 0x%lx\n", pgd, pgd_val(*pgd));
//      printk(KERN_INFO "Protection bits: %s%s%s\n", 
//         (pgd_val(*pgd) & _PAGE_USER) ? "USER " : "", 
//         (pgd_val(*pgd) & _PAGE_RW) ? "RW " : "RO ",
//         (pgd_val(*pgd) & _PAGE_NX) ? "NO-EXEC" : "EXEC"); 


//     printk(KERN_INFO "if have p4d: %d\n", pgtable_l5_enabled());
//     p4d = p4d_offset(pgd, addr);
//     if(p4d_none(*p4d) || p4d_bad(*p4d)) {
//         printk(KERN_INFO "P4D invalid or not present for address 0x%lx\n", addr);
//          return 3;
//     }
//     printk(KERN_INFO "P4D found at %px, value: 0x%lx\n", p4d, p4d_val(*p4d));
//     printk(KERN_INFO "Protection bits: %s%s%s\n", 
//         (p4d_val(*p4d) & _PAGE_USER) ? "USER " : "", 
//          (p4d_val(*p4d) & _PAGE_RW) ? "RW " : "RO ",
//         (p4d_val(*p4d) & _PAGE_NX) ? "NO-EXEC" : "EXEC"); 


//     pud = pud_offset(p4d, addr);
//     if(pud_none(*pud) || pud_bad(*pud)) {
//         printk(KERN_INFO "PUD invalid or not present for address 0x%lx\n", addr);
//         return 4;
//     }
//     printk(KERN_INFO "PUD found at %px, value: 0x%lx\n", pud, pud_val(*pud));
//     printk(KERN_INFO "Protection bits: %s%s%s\n", 
//         (pud_val(*pud) & _PAGE_USER) ? "USER " : "", 
//         (pud_val(*pud) & _PAGE_RW) ? "RW " : "RO ",
//         (pud_val(*pud) & _PAGE_NX) ? "NO-EXEC" : "EXEC"); 


//     pmd = pmd_offset(pud, addr);
//     if(pmd_none(*pmd) || pmd_bad(*pmd)) {
//         printk(KERN_INFO "PMD invalid or not present for address 0x%lx\n", addr);
//         return 5;
//     }
//     printk(KERN_INFO "PMD found at %px, value: 0x%lx\n", pmd, pmd_val(*pmd));
//     if(pmd_huge(*pmd)) {
//         printk(KERN_INFO "This is a huge page mapping at PMD level\n");
//         printk(KERN_INFO "PMD flags: %s %s %s\n", (pmd_val(*pmd) & _PAGE_USER) ? "USER " : "",
//                                                     (pmd_val(*pmd) & _PAGE_RW) ? "RW " : "RO ",
//                                                     (pmd_val(*pmd) & _PAGE_NX) ? "EXEC " : "NO-EXEC");
//         return 6;
//     }
//     printk(KERN_INFO "Protection bits: %s%s%s\n", 
//             (pmd_val(*pmd) & _PAGE_USER) ? "USER " : "", 
//             (pmd_val(*pmd) & _PAGE_RW) ? "RW " : "RO ",
//             (pmd_val(*pmd) & _PAGE_NX) ? "NO-EXEC" : "EXEC"); 
    
    
//     pte = pte_offset_map(pmd, addr);
//     if(!pte) {
//          printk(KERN_INFO "Filed to map PTE for address 0x%lx\n", addr);
//         return 7;
//     }
//     if(pte_none(*pte)) {
//         printk(KERN_INFO "PTE not present for address 0x%lx\n", addr);
//         pte_unmap(pte);
//          return 8;
//     }
//     printk(KERN_INFO "PTE found at %px, value: 0x%lx\n", pte, pte_val(*pte)); 
//     printk(KERN_INFO "Page frame number: 0x%lx\n", pte_pfn(*pte)); 
//     printk(KERN_INFO "Protection bits: %s%s%s\n", 
//             (pte_val(*pte) & _PAGE_USER) ? "USER " : "", 
//             (pte_val(*pte) & _PAGE_RW) ? "RW " : "RO ",
//             (pte_val(*pte) & _PAGE_NX) ? "NO-EXEC" : "EXEC"); 
//     if (!(pte_val(*pte) & _PAGE_PRESENT)) 
//          printk(KERN_INFO "Warning: Page is not present!\n");

//     // test_fun(15);
//     return -1;
// }
// EXPORT_SYMBOL(get_page_table);
int modify_page_table(unsigned long addr, unsigned long pfn, bool read_flag, bool write_flag, bool exec_flag)
{
    printk(KERN_INFO "%s\n", __func__);
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    struct mm_struct *mm = current->mm;
    if(!mm) {
        printk(KERN_ERR "No mm_struct for current process\n");
        return 1;
    }
    pgd = pgd_offset(mm, addr);
    if(pgd_none(*pgd) || pgd_bad(*pgd)) {
        printk(KERN_INFO "PGD invalid or not present for address 0x%lx\n", addr);
         return 2;
    }
    printk(KERN_INFO "PGD found at %p, value: 0x%lx\n", pgd, pgd_val(*pgd));
    printk(KERN_INFO "Protection bits: %s%s%s\n", 
        (pgd_val(*pgd) & _PAGE_USER) ? "USER " : "", 
        (pgd_val(*pgd) & _PAGE_RW) ? "RW " : "RO ",
        (pgd_val(*pgd) & _PAGE_NX) ? "NO-EXEC" : "EXEC"); 


    printk(KERN_INFO "if have p4d: %d\n", pgtable_l5_enabled());
    p4d = p4d_offset(pgd, addr);
    if(p4d_none(*p4d) || p4d_bad(*p4d)) {
        printk(KERN_INFO "P4D invalid or not present for address 0x%lx\n", addr);
         return 3;
    }
    printk(KERN_INFO "P4D found at %p, value: 0x%lx\n", p4d, p4d_val(*p4d));
    printk(KERN_INFO "Protection bits: %s%s%s\n", 
        (p4d_val(*p4d) & _PAGE_USER) ? "USER " : "", 
        (p4d_val(*p4d) & _PAGE_RW) ? "RW " : "RO ",
        (p4d_val(*p4d) & _PAGE_NX) ? "NO-EXEC" : "EXEC"); 


    pud = pud_offset(p4d, addr);
    if(pud_none(*pud) || pud_bad(*pud)) {
        printk(KERN_INFO "PUD invalid or not present for address 0x%lx\n", addr);
        return 4;
    }
    printk(KERN_INFO "PUD found at %p, value: 0x%lx\n", pud, pud_val(*pud));
    printk(KERN_INFO "Protection bits: %s%s%s\n", 
        (pud_val(*pud) & _PAGE_USER) ? "USER " : "", 
        (pud_val(*pud) & _PAGE_RW) ? "RW " : "RO ",
        (pud_val(*pud) & _PAGE_NX) ? "NO-EXEC" : "EXEC"); 


    pmd = pmd_offset(pud, addr);
    if(pmd_none(*pmd) || pmd_bad(*pmd)) {
        printk(KERN_INFO "PMD invalid or not present for address 0x%lx\n", addr);
        return 5;
    }
    printk(KERN_INFO "PMD found at %p, value: 0x%lx\n", pmd, pmd_val(*pmd));
    if(pmd_huge(*pmd)) {
        printk(KERN_INFO "This is a huge page mapping at PMD level\n");
        printk(KERN_INFO "PMD flags: %s %s %s\n", (pmd_val(*pmd) & _PAGE_USER) ? "USER " : "",
                                                    (pmd_val(*pmd) & _PAGE_RW) ? "RW " : "RO ",
                                                    (pmd_val(*pmd) & _PAGE_NX) ? "EXEC " : "NO-EXEC");
        return 6;
    }
    printk(KERN_INFO "Protection bits: %s%s%s\n", 
            (pmd_val(*pmd) & _PAGE_USER) ? "USER " : "", 
            (pmd_val(*pmd) & _PAGE_RW) ? "RW " : "RO ",
            (pmd_val(*pmd) & _PAGE_NX) ? "NO-EXEC" : "EXEC"); 
    
    
    pte = pte_offset_map(pmd, addr);
    if(!pte) {
         printk(KERN_INFO "Filed to map PTE for address 0x%lx\n", addr);
        return 7;
    }
    if(pte_none(*pte)) {
        printk(KERN_INFO "PTE not present for address 0x%lx\n", addr);
        pte_unmap(pte);
         return 8;
    }
    printk(KERN_INFO "PTE found at %p, value: 0x%lx\n", pte, pte_val(*pte)); 
    printk(KERN_INFO "Page frame number: 0x%lx\n", pte_pfn(*pte)); 
    printk(KERN_INFO "Protection bits: %s%s%s\n", 
            (pte_val(*pte) & _PAGE_USER) ? "USER " : "", 
            (pte_val(*pte) & _PAGE_RW) ? "RW " : "RO ",
            (pte_val(*pte) & _PAGE_NX) ? "NO-EXEC" : "EXEC"); 
    if(!(pte_val(*pte) & _PAGE_PRESENT)) 
         printk(KERN_INFO "Warning: Page is not present!\n");
    pteval_t tmp_pte_val = pte_val(*pte);
    if(read_flag || write_flag) {
        tmp_pte_val |= _PAGE_RW;
    } else {
        tmp_pte_val &= (~_PAGE_RW);
    }
    if(exec_flag) {
        tmp_pte_val &= ~_PAGE_NX;
    } else {
        tmp_pte_val |= _PAGE_NX;
    }

    // 修改pfn
    printk(KERN_INFO "tmp_pte_val: 0x%lx", tmp_pte_val);
    tmp_pte_val &= PFN_CHANGE_MASK;
    printk(KERN_INFO "tmp_pte_val: 0x%lx  (pfn << PAGE_SHIFT): 0x%lx", tmp_pte_val, (pfn << PAGE_SHIFT));
    tmp_pte_val  = tmp_pte_val | (unsigned long)(pfn << PAGE_SHIFT);
    printk(KERN_INFO "tmp_pte_val: 0x%lx", tmp_pte_val);
    pte->pte = tmp_pte_val;

    printk(KERN_INFO "again: Page frame number: 0x%lx\n", pte_pfn(*pte)); 
    printk(KERN_INFO "again: Protection bits: %s%s%s\n", 
            (pte_val(*pte) & _PAGE_USER) ? "USER " : "", 
            (pte_val(*pte) & _PAGE_RW) ? "RW " : "RO ",
            (pte_val(*pte) & _PAGE_NX) ? "NO-EXEC" : "EXEC"); 
    if(!(pte_val(*pte) & _PAGE_PRESENT)) 
         printk(KERN_INFO "again: Warning: Page is not present!\n");
    return -1;
}

int get_phy_mem(void* user_ptr, void* kern_ptr)
{
    printk(KERN_INFO "%s\n", __func__);

    // get_page_table(user_ptr);

    printk(KERN_INFO "k: %lx  u:%lx\n", kern_ptr, user_ptr);
    struct page *page_ptr;
    get_user_pages(user_ptr, 1, FOLL_WRITE, &page_ptr, NULL);
    // printk(KERN_INFO "virt_to_phys  k: 0x%lx  u1:0x%lx  u2:%lx\n", virt_to_phys(kern_ptr), virt_to_phys(user_ptr), page_to_phys(page_ptr));
    printk(KERN_INFO "vmalloc_to_pfn k: 0x%lx   page_to_phys u: 0x%lx \n", vmalloc_to_pfn(kern_ptr), page_to_phys(page_ptr));
    unsigned char* kern_addr = (unsigned char*)kern_ptr;
    unsigned char user_addr[PAGE_SIZE];
    copy_from_user(user_addr, user_ptr, PAGE_SIZE);
    int index = 0;
    while(index < 20) {
        printk(KERN_INFO "index: %d  k:0x%02x u:0x%02x\n", index, kern_addr[index], user_addr[index]);
        index++;
    }
    return 0;
}

void copy_fun(void __user* dest, void* src, size_t size, size_t offset)
{
    int a = 5;
    // a = test_fun(a);
    size_t page_num = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    size_t bytes = PAGE_SIZE * page_num;
    printk(KERN_INFO "SRC: 0x%lx  dest: 0x%lx  page_num: %d  offset:%d\n", src, dest, page_num, offset);

    // get_page_table(dest);
    if(!access_ok(dest, bytes)) {
        printk(KERN_ERR "user space cannot access\n");
        return;
    }
    if(copy_to_user(dest, src, bytes)) {
        printk(KERN_ERR "copy to user error\n");
        return; 
    }
}

int send_to_user(int _pid, user_request_t* request)
{
    printk(KERN_INFO "%s\n", __func__);

    // kernel_response_t* response = (kernel_response_st)kmalloc(sizeof(kernel_response_t), GFP_KERNEL);
    struct sk_buff *nl_skb;
    struct nlmsghdr *nlh;
    int ret;
    nl_skb = nlmsg_new(sizeof(kernel_response_t), GFP_ATOMIC);
    if(!nl_skb) {
        return -1;
    }
    nlh = nlmsg_put(nl_skb, 0, 0, NETLINK_TEST, sizeof(kernel_response_t), 0);
    if(nlh == NULL) {
        nlmsg_free(nl_skb);
        return -1;
    }
    ret = netlink_unicast(netlinkfd, nl_skb, _pid, MSG_DONTWAIT);
    return ret;
}

static void netlink_rcv_msg(struct sk_buff *skb)
{
    printk(KERN_INFO "%s\n", __func__);

    struct nlmsghdr *nlh = NULL;
    char *data = NULL;
    user_request_t *request;
    nlh = nlmsg_hdr(skb);
    if(skb->len >= NLMSG_SPACE(0)) {
        request = (user_request_t*)NLMSG_DATA(nlh);
        if(request) {
            user_process.pid = nlh->nlmsg_pid;
            send_to_user(user_process.pid, request);
        }
    } else {
        printk("%s error skb, length: %d\n", __func__, skb->len);
    }
    // get_page_table(request->addr);
    unsigned long virt_addr = (unsigned long)test_fun;
    printk("test_fun virt addr: 0x%lx  virt_to_phys: 0x%lx  vmalloc_to_pfn: 0x%lx\n", virt_addr, virt_to_phys(test_fun), vmalloc_to_pfn(test_fun));
    // printk("get_page_table() ret: %d\n", get_page_table(request->addr));
    unsigned long pfn = (unsigned long)vmalloc_to_pfn(test_fun);

    printk(KERN_INFO "PFN: 0x%lx\n", pfn);
    printk("modify_page_table() ret: %d\n", modify_page_table(request->addr, pfn, 1, 0, 1)); // virt_addr, pfn, read_flag, write_flag, exec_flag
    // flush_tlb_page(find_vma(current->mm, request->addr), srequest->addr);
    // copy_fun(request->addr, test_fun, FUN_SIZE, FUN_OFFSET);
    // 按照一页进行拷贝
    get_phy_mem(request->addr, virt_addr & PAGE_MASK);
    // copy_fun(request->addr, virt_addr & PAGE_MASK, FUN_SIZE, FUN_OFFSET);
    // get_phy_mem(request->addr, virt_addr & PAGE_MASK);
}

struct netlink_kernel_cfg cfg = {
    .input = netlink_rcv_msg,
    .groups = 0,
    .flags = 0,
    .cb_mutex = NULL,
    .bind = NULL,
};

static int __init remap_pfn_init(void)
{
	int ret = 0;
    ret = test_fun(10);
    printk(KERN_INFO "ret: %d\n", ret);

    netlinkfd = (struct sock*)netlink_kernel_create(&init_net,  NETLINK_TEST, &cfg);
    if(netlinkfd == NULL) {
        printk(KERN_ERR "CANNOT create a netlink socket\n");
        return -1;
    }

err:
	return ret;
}

static void __exit remap_pfn_exit(void)
{
    if(netlinkfd) {
        netlink_kernel_release(netlinkfd);
        netlinkfd = NULL;
    }
}

module_init(remap_pfn_init);
module_exit(remap_pfn_exit);
MODULE_LICENSE("GPL");