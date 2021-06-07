#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/list.h>

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
asmlinkage long (*orig_clone)(const struct pt_regs *);

/* use by my_openat*/
/*
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

*/
char *target[NUM_OF_TARGET] = {"/proc/cpuinfo", "/proc/net/tcp", "/proc/filesystems"};

/* for binded list*/
struct k_list {
    char *filename;
    int count;
    struct list_head test_list;
};

struct list_head test_head;


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


/*=========== functions used by my_openat ===============*/

/* prevent doubly umount, return counts of specific filename*/
int check_binded(char filename[]){
    struct list_head *ptr;
    struct k_list *entry;

    list_for_each(ptr, &test_head){
        entry = list_entry(ptr, struct k_list, test_list);
        if (entry->filename == filename){
            entry->count += 1;
            return entry->count;
        }
    }

    struct k_list *new;

    new = kmalloc(sizeof(struct k_list *), GFP_KERNEL);
    new->filename = filename;
    new->count = 1;
    list_add(&new->test_list, &test_head);
    return new->count;
}

int execute_tracer(int pid, char filename[]){
    int ret = -1;

    char exec[NAME_MAX];
    char str[] = "/home/minyeon/syscall_hooking/tracer %d %s > /home/minyeon/syscall_hook                                                            ing/tracer_out";
    snprintf(exec, sizeof(exec), str, pid, filename);

    char path[] = "/bin/bash";
    char *argv[] = {path, "-c", exec, NULL};
    char *envp[] = {"HOME=/", "PATH=/sbin:/bin:/usr/bin", NULL};

    ret = call_usermodehelper(path, argv, envp, UMH_WAIT_PROC);
    //pr_info("ret %d pid %d\n", ret, current->tgid);
    return ret;
}

/* get the full path of exe */
char *get_path(void) {
	char *pathname, *p;
	struct mm_struct *mm;

	mm = current->mm;
	if (mm){
		down_read(&mm->mmap_lock);
		if (mm->exe_file){
			pathname = kmalloc(PATH_MAX, GFP_ATOMIC);
			if (pathname){
				p = d_path(&mm->exe_file->f_path, pathname, PATH_MAX);
			}
		}
		up_read(&mm->mmap_lock);
	}
	return p;
}

/* =======================================================================*/

asmlinkage int my_openat(const struct pt_regs *regs)
{
    char __user *filename = (char *)regs->si;
    char file_name[NAME_MAX] = {0};
    char *file;
    int i;
    int count;

    long error = strncpy_from_user(file_name, filename, NAME_MAX);

    for (i = 0; i < NUM_OF_TARGET; i++) //cmp with all target file
    {
        if (error && (target[i] != NULL) && strstr(file_name, target[i]))
        {
			/* p: get the full path of executable */
            char *pathname, *p;
            struct mm_struct *mm;
            mm = current->mm;
            if (mm){
                down_read(&mm->mmap_lock);
                if(mm->exe_file){
                    pathname = kmalloc(PATH_MAX, GFP_ATOMIC);
                    if (pathname){
                        p = d_path(&mm->exe_file->f_path, pathname, PATH_MAX);
                        pr_info("pathname %s\n", p);
                    }
                }
                up_read(&mm->mmap_lock);
            }

            pr_info("[info] %s : Detected !! Pid %d (\"%s\") Try to open %s\n", __func__,                                                             current->tgid, current->group_leader->comm, file_name);

            pr_info("%s(pid %d)(state %d) -> %s(pid %d)(%d) -> %s(pid %d)(%d)-> %s                                                             %d %d -> %s %d %d-> %s %d %d\n",
                                current->comm, current->tgid, current->in_execve,
                                current->parent->comm, current->parent->tgid, current->parent->in_execve,
                                current->parent->parent->comm, current->parent->parent->tgid, current->parent->parent->in_execve,
                                current->parent->parent->parent->comm, current->parent->parent->parent->tgid, current->parent->parent->parent->in_execve,
                                current->parent->parent->parent->parent->comm, current->parent->parent->parent->parent->tgid, current->parent->parent->parent->parent->in_execve,
                                current->parent->parent->parent->parent->parent->comm, current->parent->parent->parent->parent->parent->tgid, current->parent->parent->parent->parent->parent->in_execve);
            check_binded(target[i]);
            execute_tracer(current->tgid, target[i]);
        }
    }
    return orig_openat(regs);
}

/*=========== for symbol of sys_call_table including modifying ==================*/

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

static unsigned long get_sys_call_table_ptr(void) {
	int ret;

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

void wp_change(unsigned long cr0) {
    __asm__ __volatile__("mov %0,%%cr0" : "+r"(cr0));
}

/* ======================================================================================== */

static int __init m_init(void) {
	pr_info("[INFO] Module Loaded!\n");
    sys_call_table_ptr = (void *)get_sys_call_table_ptr();

    if (!sys_call_table_ptr){
        pr_err("krpobe register fail");
        return -1;
    }
    pr_info("sys_call_table address = 0x%lx\n", sys_call_table_ptr);

    orig_openat = sys_call_table_ptr[__NR_openat];
    pr_info("origin openat address = 0x%p\n", orig_openat);

	/* modify sys_call_table*/
    wp_change(read_cr0() & (~0x10000)); //disable cr0.wp
    sys_call_table_ptr[__NR_openat] = my_openat;
    wp_change(read_cr0() | 0x10000);    //enable cr0.wp
    pr_info("my_openat address: 0x%p\n", sys_call_table_ptr[__NR_openat]);
    
	INIT_LIST_HEAD(&test_head);

    return 0;
}

static void __exit m_exit(void) {
	/* restore orig sys_call_table*/
    wp_change(read_cr0() & (~0x10000));
    sys_call_table_ptr[__NR_openat] = orig_openat;
    sys_call_table_ptr[__NR_clone] = orig_clone;
    wp_change(read_cr0() | 0x10000);
    orig_openat = NULL;
    orig_clone = NULL;
    pr_info("restore sys_openat = 0x%p\n", sys_call_table_ptr[__NR_openat]);
    pr_info("restore sys_clone = 0x%p\n", sys_call_table_ptr[__NR_clone]);

    struct list_head *ptr;
    struct k_list *entry;
    char *file;

    list_for_each(ptr, &test_head){
        entry = list_entry(ptr, struct k_list, test_list);
        pr_info("%s: cnt:%d\n", entry->filename, entry->count);

    }

    pr_info("[INFO] Module Unloaded\n");
}

module_init(m_init);
module_exit(m_exit);

