#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>

#define MAX_SYMBOL_LEN    64
static char symbol[MAX_SYMBOL_LEN] = "_do_fork";
module_param_string(symbol, symbol, sizeof(symbol), 0644);

/* For each probe you need to allocate a kprobe structure */
static struct kprobe kp = { //定义一个实例kp并初始化symbol_name为"_do_fork"，将探测_do_fork函数。
    .symbol_name    = symbol,
};

/* kprobe pre_handler: called just before the probed instruction is executed */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
#ifdef CONFIG_X86
    pr_info("<%s> pre_handler: p->addr = %pF, ip = %lx, flags = 0x%lx\n",
        p->symbol_name, p->addr, regs->ip, regs->flags);
#endif
#ifdef CONFIG_ARM64
    pr_info("<%s> pre_handler: p->addr = %pF, pc = 0x%lx,"
            " pstate = 0x%lx\n",
        p->symbol_name, p->addr, (long)regs->pc, (long)regs->pstate);
#endif

    /* A dump_stack() here will give a stack backtrace */
    return 0;
}

/* kprobe post_handler: called after the probed instruction is executed */
static void handler_post(struct kprobe *p, struct pt_regs *regs,
                unsigned long flags)
{
#ifdef CONFIG_X86
    pr_info("<%s> post_handler: p->addr = %pF, flags = 0x%lx\n",
        p->symbol_name, p->addr, regs->flags);
#endif
#ifdef CONFIG_ARM64
    pr_info("<%s> post_handler: p->addr = %pF, pstate = 0x%lx\n",
        p->symbol_name, p->addr, (long)regs->pstate);
#endif
}

/*
 * fault_handler: this is called if an exception is generated for any
 * instruction within the pre- or post-handler, or when Kprobes
 * single-steps the probed instruction.
 */
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
    pr_info("fault_handler: p->addr = %pF, trap #%dn", p->addr, trapnr);
    /* Return 0 because we don't handle the fault. */
    return 0;
}

static int __init kprobe_init(void)
{
    int ret;
    kp.pre_handler = handler_pre;// 初始化kp的三个回调函数。
    kp.post_handler = handler_post;
    kp.fault_handler = handler_fault;

    ret = register_kprobe(&kp);// 注册kp探测点到内核。
    if (ret < 0) {
        pr_err("register_kprobe failed, returned %d\n", ret);
        return ret;
    }
    pr_info("Planted kprobe at %pF\n", kp.addr);
    return 0;
}

static void __exit kprobe_exit(void)
{
    unregister_kprobe(&kp);
    pr_info("kprobe at %pF unregistered\n", kp.addr);
}

module_init(kprobe_init)
module_exit(kprobe_exit)
MODULE_LICENSE("GPL");