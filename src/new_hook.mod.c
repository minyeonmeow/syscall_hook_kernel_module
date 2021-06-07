#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(.gnu.linkonce.this_module) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section(__versions) = {
	{ 0x9de7765d, "module_layout" },
	{ 0x67c0c54c, "pv_ops" },
	{ 0xd1fbc889, "unregister_kprobe" },
	{ 0x8ee53e31, "register_kprobe" },
	{ 0x53b954a2, "up_read" },
	{ 0xc5850110, "printk" },
	{ 0x115c2b89, "d_path" },
	{ 0x668b19a1, "down_read" },
	{ 0x2ea2c95c, "__x86_indirect_thunk_rax" },
	{ 0x1e6d26a8, "strstr" },
	{ 0x24428be5, "strncpy_from_user" },
	{ 0xebbe12f0, "current_task" },
	{ 0xc959d152, "__stack_chk_fail" },
	{ 0xa7eedcc4, "call_usermodehelper" },
	{ 0x656e4a6e, "snprintf" },
	{ 0xb5f17439, "kmem_cache_alloc_trace" },
	{ 0xcbf895e0, "kmalloc_caches" },
	{ 0xbdfb6dbb, "__fentry__" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "496F616DF887FEE3422EBA7");
