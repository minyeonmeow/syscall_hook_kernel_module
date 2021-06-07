#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>

#define KPROBE_PRE_HANDLER(fname) static int __kprobes fname(struct kprobe *p, struct pt_regs *regs)
#define NUM_OF_TARGET 10

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Minyeon");

/* variable for finding sys_call_table by kprobe*/
long unsigned int kln_addr = 0;
unsigned long (*kln_pointer)(const char *name) = NULL;
static struct kprobe kp0, kp1;
static void **sys_call_table_ptr;
asmlinkage int (*orig_openat)(const struct pt_regs *);

/* declare of function*/
void execute_tracer(int, char[]);

/* use by my_openat*/
char *target[NUM_OF_TARGET] = {"/proc/net/route",
                               "/proc/filesystems",
                               "/proc/stat",
                               "/proc/net/tcp",
                               "/proc/meminfo",
                               "/proc/net/dev",
                               "/proc/cpuinfo",
                               "/sys/firmware/dmi/tables/smbios_entry_point",
                               "/sys/firmware/dmi/tables/DMI",
                               "/proc/%d/stat"};

char *binded[NUM_OF_TARGET] = {};

/* define kprobe pre handler*/
KPROBE_PRE_HANDLER(handler_pre0)
{
    kln_addr = (--regs->ip);
    return 0;
}

KPROBE_PRE_HANDLER(handler_pre1)
{
    return 0;
}


/*================================================================================*/
void execute_tracer(int pid, char filename[NAME_MAX])
{
    pr_info("%d %s\n", pid, filename);

    int ret = -1;

    char exec[NAME_MAX];
    char str[] = "/home/minyeon/syscall_hooking/tracer %d > /home/minyeon/syscall_hooking/trace_out";
    snprintf(exec, sizeof(exec), str, pid);
    //pr_info("%s\n", exec);

    char path[] = "/bin/bash";
    char *argv[] = {path, "-c", exec, NULL};
    char *envp[] = {"HOME=/", "PATH=/sbin:/bin:/usr/bin", NULL};

    pr_info("call_usermodehelper...\n");

    ret = call_usermodehelper(path, argv, envp, UMH_WAIT_PROC);
    pr_info("ret %d\n", ret);
}



asmlinkage int my_openat(const struct pt_regs *regs)
{
    char __user *filename = (char *)regs->si;
    char file_name[NAME_MAX] = {0};
    int i;

    long error = strncpy_from_user(file_name, filename, NAME_MAX);

    for (i = 0; i < NUM_OF_TARGET; i++) //cmp with all target file
    {
        if (error && (target[i] != NULL) && strstr(file_name, target[i]))
        {
            pr_info("[info] %s : Detected !! Pid %d (\"%s\") Try to open %s\n", __func__, current->parent->tgid, current->parent->group_leader->comm, file_name);
            pr_info("[info] %s -> %s -> %s -> %s -> %s -> %s\n", current->group_leader->comm, current->parent->group_leader->comm, current->parent->parent->group_leader->comm, current->parent->parent->parent->group_leader->comm, current->parent->parent->parent->parent->group_leader->comm, current->parent->parent->parent->parent->parent->group_leader->comm);
            //execute_tracer(current->tgid, file_name);
        }
    }
    return orig_openat(regs);
}

/*================================================================================*/


static int do_register_kprobe(struct kprobe *kp, char *symbol_name, void *handler)
{
  int ret;

  kp->symbol_name = symbol_name;
  kp->pre_handler = handler;

  ret = register_kprobe(kp);
  if (ret < 0) {
    pr_err("register_probe() for symbol %s failed, returned %d\n", symbol_name, ret);
    return ret;
  }
  return ret;
}

static unsigned long get_sys_call_table_ptr(void)
{
  int ret;

  pr_info("module loaded\n");

  ret = do_register_kprobe(&kp0, "kallsyms_lookup_name", handler_pre0);
  if (ret < 0)
    return 0;

  ret = do_register_kprobe(&kp1, "kallsyms_lookup_name", handler_pre1);
  if (ret < 0) {
    unregister_kprobe(&kp0);
    return 0;
  }
  unregister_kprobe(&kp0);
  unregister_kprobe(&kp1);

  kln_pointer = (unsigned long (*)(const char *name)) kln_addr; //kallsym_look_up ptr

  return kln_pointer("sys_call_table");
}

void wp_change(unsigned long cr0)
{
  __asm__ __volatile__("mov %0,%%cr0" : "+r"(cr0));
}

static int __init m_init(void)
{
  sys_call_table_ptr = (void *)get_sys_call_table_ptr();

  if (!sys_call_table_ptr){
    pr_err("krpobe register fail");
	return -1;
  }
  pr_info("sys_call_table address = 0x%lx\n", sys_call_table_ptr);

  orig_openat = sys_call_table_ptr[__NR_openat];
  pr_info("origin openat address = 0x%p\n", orig_openat);

  wp_change(read_cr0() & (~0x10000)); //disable cr0.wp
  sys_call_table_ptr[__NR_openat] = my_openat;
  wp_change(read_cr0() | 0x10000);    //enable cr0.wp
  pr_info("my_openat address: 0x%p\n", sys_call_table_ptr[__NR_openat]);

  return 0;
}

static void __exit m_exit(void)
{
  wp_change(read_cr0() & (~0x10000));
  sys_call_table_ptr[__NR_openat] = orig_openat;
  wp_change(read_cr0() | 0x10000);
  orig_openat = NULL;
  pr_info("restore sys_openat = 0x%p\n", sys_call_table_ptr[__NR_openat]);
  pr_info("module unloaded\n");
}

module_init(m_init);
module_exit(m_exit);

