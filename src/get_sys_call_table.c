#include <linux/module.h>
#include <linux/kernel.h>

unsigned long *sys_call_table;

struct {
    unsigned short limit;
    unsigned long base;
} __attribute__ ((packed))idtr;

struct {
    unsigned short off1;
    unsigned short sel;
    unsigned char none, flags;
    unsigned short off2;
} __attribute__ ((packed))idt;


void *memmem ( const void *haystack, size_t haystack_size, const void *needle, size_t needle_size )
{
    char *p;

    for ( p = (char *)haystack; p <= ((char *)haystack - needle_size + haystack_size); p++ )
        if ( memcmp(p, needle, needle_size) == 0 )
            return (void *)p;
        return NULL;
}


// http://bbs.chinaunix.net/thread-2143235-1-1.html
unsigned long *find_sys_call_table ( void )
{
    char **p;
    unsigned long sct_off = 0;
    unsigned char code[512];

    rdmsrl(MSR_LSTAR, sct_off);
    memcpy(code, (void *)sct_off, sizeof(code));

    p = (char **)memmem(code, sizeof(code), "\xff\x14\xc5", 3);

    if ( p )
    {
        unsigned long *sct = *(unsigned long **)((char *)p + 3);

        // Stupid compiler doesn't want to do bitwise math on pointers
        sct = (unsigned long *)(((unsigned long)sct & 0xffffffff) | 0xffffffff00000000);
        return sct;
    }
    else
        return NULL;
}


// 模块载入时被调用
static int __init init_get_sys_call_table(void)
{
    sys_call_table = find_sys_call_table();
    printk("The sys_call_table address is:%lx\n",(unsigned long)sys_call_table);
    return 0;
}


// 模块卸载时被调用
static void __exit exit_get_sys_call_table(void)
{
    printk("Get sys_call_table finish!\n");
}

module_init(init_get_sys_call_table);
module_exit(exit_get_sys_call_table);


MODULE_LICENSE("GPL2.0");
MODULE_AUTHOR("curits");

