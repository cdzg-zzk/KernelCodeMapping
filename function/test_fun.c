#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

// 导出符号，使得其他模块可以调用该函数

int extern_test_fun(int a, int b);

// 定义 test_fun 函数
int extern_test_fun(int a, int b)
{
    return a + 2 * b;
}
EXPORT_SYMBOL(extern_test_fun);
// 模块初始化函数
static int __init my_module_init(void)
{
    return 0;
}

// 模块退出函数
static void __exit my_module_exit(void)
{
    return;
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel module with exported function test_fun.");
