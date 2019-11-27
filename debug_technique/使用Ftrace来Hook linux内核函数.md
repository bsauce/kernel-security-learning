# 【Linux内核调试】使用Ftrace来Hook linux内核函数

目标：hook几个Linux内核函数调用，如打开文件和启动进程，并利用它来启用系统活动监控并抢先阻止可疑进程。

## 一、方案比较

#### 1. 使用Linux安全API

方法：内核代码的关键点包含安全函数调用，这些调用可能触发安全模块安装的回调，该模块可以分析特定操作的上下文，并决定是允许还是禁止它。

限制：安全模块无法动态加载，所以需要重新编译内核。

#### 2. 修改系统调用表

方法：所有Linux系统调用处理程序都存储在sys_call_table表中，可以保存旧的处理程序值，并将自己的处理程序添加到表中，这样就能hook任何系统调用。

优点：一是能够完全控制所有系统调用；二是性能开销较小，包含更新系统调用表、监视、调用原始系统调用处理程序；三是通用性较好，不依赖内核版本。

缺点：一是实现较复杂，需查看系统调用表、绕过内存写保护、确保处理程序的安全性；二是有些处理程序无法替换，如有些优化要求在汇编中实现系统调用处理程序；三是只能hook系统调用，限制了入口点。

#### 3.Kprobes

方法：可以为任何内核指令、函数入口和函数返回点安装处理程序，处理程序可以访问寄存器并更改它们。

优点：一是API很成熟；二是能跟踪内核中任意点，kprobes通过在内核代码中嵌入断点（int3指令）实现。跟踪函数内部的特定指令很有用。

缺点：一是技术复杂，若要获取函数参数或局部变量值，需知道堆栈具体位置及所在寄存器，并手动取出，若要阻止函数调用，还需手动修改进程状态；二是开销太大，超过了修改系统调用表的成本；三是禁用抢占，kprobes基于中断和故障，所以为了执行同步，所有处理程序需以禁用的抢占方式执行，导致的限制是，处理程序中不能等待、分配大量内存、处理输入输出、在信号量和计时器中休眠。

#### 4.拼接

方法：将函数开头的指令替换为通向处理程序的无条件跳转，处理完成后再执行原始指令，再跳回截断函数前执行。类似于kprobes。

优点：一是不需要设置内核编译选项，可在任何函数开头实现；二是开销低，两次跳转即可返回到原始点。

缺点：技术复杂。

- 同步挂钩安装和删除（如果在更换指令期间调用了该函数）
- 使用可执行代码绕过内存区域的写保护
- 替换指令后使CPU缓存失效
- 拆卸已替换的指令，以便将它们作为一个整体进行复制
- 检查替换后的函数是否没有跳转
- 检查替换后的函数是否可以移动到其他位置

## 二、使用Ftrace hook函数

#### 1.简介

ftrace提供很多函数集，可显示调用图、跟踪函数调用频率和长度、过滤特定函数。ftrace的实现基于编译器选项-pg和-mfentry，这些内核选项在每个函数的开头插入一个特殊跟踪函数的调用—mcount()或**fentry** ()，用于实现ftrace框架。

但是每个函数调用ftrace会使性能降低，所以有一种优化机制——动态trace。内核知道调用mcount()或**fentry** ()的位置，在早期阶段将机器码替换为nop，当打开Linux内核跟踪时，ftrace调用会被添加到指定的函数中。

#### 2.函数说明

以下结构用于描述每个钩子函数：

```c
/*
name: 被hook的函数名
function: 钩子函数的地址(替代被hook函数)
original: 指针，指向存储被hook函数的地址的地方
address:  被hook函数的地址
ops:      ftrace服务信息
*/
struct ftrace_hook {
        const char *name;
        void *function;
        void *original;

        unsigned long address;
        struct ftrace_ops ops;
};
```

可以只填写三个字段：name、function、original。

```c
#define HOOK(_name, _function, _original) \
        { \
            .name = (_name), \
            .function = (_function), \
            .original = (_original), \
        }

static struct ftrace_hook hooked_functions[] = {
        HOOK("sys_clone", fh_sys_clone, &real_sys_clone),
        HOOK("sys_execve", fh_sys_execve, &real_sys_execve),
};
```

钩子函数包装的结构如下：

```c
/*
这是个指向原始execve()的指针，可被wrapper调用。未改变参数顺序和类型、返回值
asmlinkage:调用函数的时候参数不是通过栈传递，而是直接放到寄存器里
 */
static asmlinkage long (*real_sys_execve)(const char __user *filename,
                const char __user *const __user *argv,
                const char __user *const __user *envp);
/*
fh_sys_execve函数将代替被hook函数执行，它的参数和原始函数一样，返回值也正常返回。该函数可在被hook函数之前、之后或替代执行。
 */
static asmlinkage long fh_sys_execve (const char __user *filename,
                const char __user *const __user *argv,
                const char __user *const __user *envp)
{
        long ret;
        pr_debug("execve() called: filename=%p argv=%p envp=%p\n",
                filename, argv, envp);
        ret = real_sys_execve(filename, argv, envp);
        pr_debug("execve() returns: %ld\n", ret);
        return ret;
}
```

#### 3.初始化ftrace

第一步是查找被hook函数的地址，通过kallsyms。

```c
static int resolve_hook_address (struct ftrace_hook *hook)

        hook->address = kallsyms_lookup_name(hook->name);

        if (!hook->address) {
                pr_debug("unresolved symbol: %s\n", hook->name);
                return -ENOENT;
        }

        *((unsigned long*) hook->original) = hook->address;

        return 0;
}
```

第二步，初始化ftrace_ops结构，需设置必要字段func\flags。

```c
int fh_install_hook (struct ftrace_hook *hook)

        int err;

        err = resolve_hook_address(hook);
        if (err)
                return err;

        hook->ops.func = fh_ftrace_thunk;
        hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
                        | FTRACE_OPS_FL_IPMODIFY;

        /* ... */
}
```

`fh_ftrace_thunk()`是ftrace在跟踪函数时的回调函数，稍后讨论。flags意义是告诉ftrace保存和恢复寄存器（以修改寄存器），我们可在回调函数中修改这些寄存器的内容（RIP）。

第三步，开始hook，首先用`ftrace_set_filter_ip()`为需要跟踪的函数打开ftrace，再调用`register_ftrace_function()`对被hook函数进行注册。记得用`ftrace_set_filter_ip()`关闭ftrace。

```c
int fh_install_hook (struct ftrace_hook *hook)
{
        /* ... */

        err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
        if (err) {
                pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
                return err;
        }

        err = register_ftrace_function(&hook->ops);
        if (err) {
                pr_debug("register_ftrace_function() failed: %d\n", err);

                /* Don’t forget to turn off ftrace in case of an error. */
                ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0); 

                return err;
        }

        return 0;
}
```

关闭钩子如下，避免钩子函数仍然在其他地方执行：

```c
void fh_remove_hook (struct ftrace_hook *hook)
{
        int err;

        err = unregister_ftrace_function(&hook->ops);
        if (err)
                pr_debug("unregister_ftrace_function() failed: %d\n", err);
        }

        err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
        if (err) {
                pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
        }
}
```

#### 4.用ftrace hook函数

原理：修改rip寄存器指向自定义的回调函数。

```c
static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                struct ftrace_ops *ops, struct pt_regs *regs)
{
        struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

        regs->ip = (unsigned long) hook->function;
}
// container_of(ptr,type,member): 已知结构体type的成员member的地址ptr，求解结构体type的起始地址。也即返回ftrace_hook结构的首地址。
// notrace说明符：如果不小心从ftrace回调中调用了一个函数，系统就不会挂起，因为ftrace正在跟踪这个函数。
```

#### 5.防止递归调用

问题：当包装函数调用原始函数时，原始函数将被ftrace再次跟踪，从而导致无穷无尽的递归。

解决：可利用`parent_ip`（调用钩子函数的返回地址）——ftrace回调参数之一，该参数通常用于构建函数调用图，但也可以用来区分跟踪函数是第一次调用还是重复调用。第一次调用时，`parent_ip`指向内核某个位置，重复调用时，`parent_ip`指向包装函数内部，只有第一次执行时执行回调函数，其他调用时需执行原始函数。

```c
static void notrace fh_ftrace_thunk (unsigned long ip, unsigned long parent_ip,
                struct ftrace_ops *ops, struct pt_regs *regs)
{
        struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
        /* Skip the function calls from the current module. */
        if (!within_module(parent_ip, THIS_MODULE))
                regs->ip = (unsigned long) hook->function;
}
```

内核中hook函数的整体执行流程可参见[Hooking linux内核函数（二）：如何使用Ftrace hook函数](https://xz.aliyun.com/t/2948)中的图示。

## 三、Ftrace评价与配置

#### 1.优缺点

优点：一是API成熟，代码简单；二是根据名称就能跟踪任何函数；三是开销较低。

缺点：一是配置上有要求，需支持kallsyms函数索引、ftrace框架；二是ftrace只能在函数入口点工作。

#### 2.配置

编译内核时需设置以下选项：

- `CONFIG_FTRACE`——Ftrace
- `CONFIG_KALLSYMS`——kallsyms
- `CONFIG_DYNAMIC_FTRACE_WITH_REGS`——动态寄存器修改
- `CONFIG_HAVE_FENTRY`——ftrace调用必须位于函数的开头（x86_64架构支持，但i386架构不支持，所以ftrace函数hooking不支持32位x86体系结构）

#### 3.启发

启发：可以hook某些函数，如堆分配函数kmalloc，记录参数和返回值。



## 参考

[示例代码](https://github.com/ilammy/ftrace-hook)

[Hooking linux内核函数（一）：寻找完美解决方案](https://xz.aliyun.com/t/2947)

[Hooking linux内核函数（二）：如何使用Ftrace hook函数](https://xz.aliyun.com/t/2948)

[Hooking linux内核函数（三）：Ftrace的主要优缺点](https://xz.aliyun.com/t/2949)