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
#include <linux/rmap.h>
#include <linux/mm_types.h>

#include <linux/types.h>
#include <net/sock.h>
#include <linux/netlink.h>

#define NETLINK_TEST 17
#define BUF_SIZE (1*PAGE_SIZE)

#define PFN_CHANGE_MASK 0xFFF8000000000FFF

#define FUN_SIZE 100
#define FUN_OFFSET 0x0


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
int get_page_table(unsigned long addr)
{
    printk(KERN_INFO "%s\n", __func__);
    printk(KERN_INFO "%lx\n", addr);

    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    struct mm_struct *mm = current->mm;
    printk(KERN_INFO "current->pid is %d   addr: %lx    mm: %p\n", current->pid, addr, mm);   // 检查PGD是否一致，虽然一致，但是还挺重要的
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
    if (!(pte_val(*pte) & _PAGE_PRESENT)) 
         printk(KERN_INFO "Warning: Page is not present!\n");

    return -1;
}


void get_pages(unsigned long addr, unsigned long kern_addr)
{
    printk(KERN_INFO "%s\n", __func__);

    struct page* kern_page = vmalloc_to_page((void*)kern_addr);
    struct page* user_page;
    int ret;

    ret = get_user_pages_fast(addr, 1, FOLL_WRITE, &user_page);
    if (ret <= 0) {
        printk(KERN_ERR "获取用户空间页失败\n");
        return;
    }

    // 打印修改前的页面信息
    printk(KERN_INFO "user_page: %p, flags: %lx, mapping: %p, index: %lx, mapcount: %d, refcount: %d\n",
           user_page, user_page->flags, user_page->mapping, user_page->index, 
           user_page->_mapcount.counter, user_page->_refcount.counter);
    printk(KERN_INFO "kern_page: %p, flags: %lx, mapping: %p, index: %lx, mapcount: %d, refcount: %d\n",
           kern_page, kern_page->flags, kern_page->mapping, kern_page->index,
           kern_page->_mapcount.counter, kern_page->_refcount.counter);
}

void modify_pages(unsigned long addr, unsigned long kern_addr)
{
    printk(KERN_INFO "%s\n", __func__);

    struct page* kern_page = vmalloc_to_page((void*)kern_addr);
    struct page* user_page;
    int ret;

    ret = get_user_pages_fast(addr, 1, FOLL_WRITE, &user_page);
    if (ret <= 0) {
        printk(KERN_ERR "获取用户空间页失败\n");
        return;
    }
    get_pages(addr, kern_addr);
    kern_page->mapping = user_page->mapping;
    kern_page->index = user_page->index;
    atomic_set(&kern_page->_mapcount, 1);
    // 1. 先解除原页面映射
    // page_remove_rmap(user_page, false);
    put_page(user_page);  // 减少原页面的引用计数

    // 2. 建立新页面映射
    get_page(kern_page);  // 增加新页面的引用计数
    // page_add_file_rmap(kern_page, false);
    // atomic_long_add(1, &current->mm->rss_stat.count[MM_FILEPAGES]);
    // atomic_long_sub(1, &current->mm->rss_stat.count[MM_ANONPAGES]);
    // current->mm->rss_stat.count[MM_FILEPAGES] = current->mm->rss_stat.count[MM_FILEPAGES] + 1;
    // current->mm->rss_stat.count[MM_ANONPAGES] = current->mm->rss_stat.count[MM_ANONPAGES] - 1;
    // 3. 更新内存统计
    // dec_mm_counter(current->mm, MM_ANONPAGES);
    // inc_mm_counter(current->mm, MM_FILEPAGES);

    // 打印修改后的页面信息
    get_pages(addr, kern_addr);
}

// 使用内联汇编直接执行TLB刷新
static inline void flush_tlb_one(unsigned long addr)
{
    asm volatile("invlpg (%0)" ::"r" (addr) : "memory");
}

int modify_page_table(unsigned long addr, unsigned long kern_addr, bool read_flag, bool write_flag, bool exec_flag)
{
    get_pages(addr, kern_addr);
    printk(KERN_INFO "%s\n", __func__);
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    struct mm_struct *mm = current->mm;
    printk(KERN_INFO "current->pid is %d   addr: %lx    mm: %p\n", current->pid, addr, mm);   // 检查PGD是否一致，虽然一致，但是还挺重要的
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
    printk(KERN_INFO "原始 pte_val: 0x%lx", tmp_pte_val);
    // 保持PRESENT位
    tmp_pte_val |= _PAGE_PRESENT;
    // 根据传入的标志位修改读写权限
    if(read_flag) {
        tmp_pte_val |= _PAGE_USER;  // 设置用户可访问
    } else {
        tmp_pte_val &= ~_PAGE_USER;
    }
    
    if(write_flag) {
        tmp_pte_val |= _PAGE_RW;
    } else {
        tmp_pte_val &= ~_PAGE_RW;
    }
    // 根据传入的标志位修改执行权限
    if(exec_flag) {
        tmp_pte_val &= ~_PAGE_NX;
    } else {
        tmp_pte_val |= _PAGE_NX;
    }


    
    // 清除原有的物理页帧号位,保留修改后的权限位
    tmp_pte_val &= PFN_CHANGE_MASK;

    
    // 设置新的物理页帧号
    unsigned long pfn = vmalloc_to_pfn((void*)kern_addr);
    tmp_pte_val |= (unsigned long)(pfn << PAGE_SHIFT);
    
    printk(KERN_INFO "新的 pte_val: 0x%lx", tmp_pte_val);
    modify_pages(addr, kern_addr);
    pte->pte = tmp_pte_val;

    // 验证修改结果
    printk(KERN_INFO "修改后的页帧号: 0x%lx\n", pte_pfn(*pte));
    printk(KERN_INFO "修改后的权限位: %s%s%s\n",
            (pte_val(*pte) & _PAGE_USER) ? "USER " : "",
            (pte_val(*pte) & _PAGE_RW) ? "RW " : "RO ",
            (pte_val(*pte) & _PAGE_NX) ? "NO-EXEC" : "EXEC"); 
    if(!(pte_val(*pte) & _PAGE_PRESENT)) 
         printk(KERN_INFO "again: Warning: Page is not present!\n");
    
    set_pte(pte, __pte(tmp_pte_val));
    // 刷新这个地址的TLB
    flush_tlb_one(addr);
    pte_unmap(pte);
    return -1;
}

int get_phy_mem(void* user_ptr, void* kern_ptr)
{
    printk(KERN_INFO "%s\n", __func__);
    struct page* user_page;
    int ret = get_user_pages_fast((unsigned long)user_ptr, 1, FOLL_WRITE, &user_page);
    if (ret <= 0) {
        printk(KERN_ERR "获取用户空间页失败\n");
        return -1;
    }
    unsigned char* kern_addr = (unsigned char*)kern_ptr;
    unsigned char user_addr[PAGE_SIZE];
    copy_from_user(user_addr, user_ptr, PAGE_SIZE);
    int index = 0;
    while(index < 20) {
        printk(KERN_INFO "index: %d  k:0x%02x u:0x%02x\n", index, kern_addr[index], user_addr[index]);
        index++;
    }
    put_page(user_page);
    return 0;
}

void copy_fun(void __user* dest, void* src, size_t size, size_t offset)
{
    int a = 5;
    // a = test_fun(a);
    size_t page_num = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    size_t bytes = PAGE_SIZE * page_num;
    printk(KERN_INFO "SRC: 0x%lx  dest: 0x%lx  page_num: %d  offset:%d\n", src, dest, page_num, offset);

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
    unsigned long virt_addr = (unsigned long)test_fun;
    printk("test_fun virt addr: 0x%lx  virt_to_phys: 0x%lx  vmalloc_to_pfn: 0x%lx\n", virt_addr, virt_to_phys(test_fun), vmalloc_to_pfn(test_fun));
    unsigned long pfn = (unsigned long)vmalloc_to_pfn(test_fun);

    printk(KERN_INFO "PFN: 0x%lx\n", pfn);
    get_page_table(request->addr);
    // get_pages(request->addr, virt_addr);
    printk("modify_page_table() ret: %d\n", modify_page_table(request->addr, virt_addr, 1, 1, 1)); // virt_addr, pfn, read_flag, write_flag, exec_flag
    // get_pages(request->addr, virt_addr);
    // flush_tlb_page(find_vma(current->mm, request->addr), srequest->addr);
    // copy_fun(request->addr, test_fun, FUN_SIZE, FUN_OFFSET);
    // 按照一页进行拷贝
    // get_page_table(request->addr);
    get_phy_mem(request->addr, virt_addr & PAGE_MASK);
    // copy_fun(request->addr, virt_addr & PAGE_MASK, FUN_SIZE, FUN_OFFSET);

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
    unsigned long kern_addr = (unsigned long)test_fun;
    struct page* kern_page = vmalloc_to_page((void*)kern_addr);
    kern_page->mapping = NULL;
    kern_page->index = 0;
    atomic_set(&kern_page->_mapcount, -1);
}

module_init(remap_pfn_init);
module_exit(remap_pfn_exit);
MODULE_LICENSE("GPL");
