# 【linux内核调试】ftrace/kprobes/SystemTap内核调试方法对比

## 一、调试简介

本文主要实践一下linux内核调试方式，并进行比较。内核调试方式在[这篇blog](https://blog.csdn.net/gatieme/article/details/68948080)中讲解的非常详细，本文只介绍几种动态的调试方法。

#### 1.ftrace

`Linux`当前版本中， 功能最强大的调试、跟踪手段。其最基本的功能是提供了动态和静态探测点，用于探测内核中指定位置上的相关信息。

静态探测点：是在内核代码中调用 ftrace 提供的相应接口实现，称之为静态是因为，是在内核代码中写死的，静态编译到内核代码中的，在内核编译后，就不能再动态修改。在开启 ftrace 相关的内核配置选项后，内核中已经在一些关键的地方设置了静态探测点，需要使用时，即可查看到相应的信息。

动态探测点：基本原理为，利用 mcount 机制，在内核编译时，在每个函数入口保留数个字节，然后在使用 ftrace时，将保留的字节替换为需要的指令，比如跳转到需要的执行探测操作的代码。

ftrace的前端工具trace-cmd，相当于是一个 `/sys/kernel/debug/tracing` 中文件系统接口的封装，为用户提供了更加直接和方便的操作。其本质就是对`/sys/kernel/debug/tracing/events` 下各个模块进行操作，收集数据并解析。

ftrace—[使用ftrace学习linux内核函数调用](https://www.cnblogs.com/zengkefu/p/6349658.html)

ftrace—[ftrace：跟踪你的内核函数！](https://linux.cn/article-9273-1.html)

ftrace—[使用ftrace调试Linux内核，第1部分](https://www.ibm.com/developerworks/cn/linux/l-cn-ftrace1/index.html)

ftrace—[使用ftrace调试Linux内核，第2部分](https://www.ibm.com/developerworks/cn/linux/l-cn-ftrace2/)

ftrace—[使用ftrace调试Linux内核，第3部分](https://www.ibm.com/developerworks/cn/linux/l-cn-ftrace3/)

ftrace—[ftrace官方文档](https://blog.csdn.net/jscese/article/details/46415531)

#### 2.kprobe

kprobe是一个轻量级的内核调试工具，也是其他更高级的内核调试（如perf和systemtap的基础）。`Kprobes` 提供了一个强行进入任何内核例程并从中断处理器无干扰地收集信息的接口，使用 `Kprobes` 可以收集处理器寄存器和全局数据结构等调试信息。开发者甚至可以使用 `Kprobes` 来修改 寄存器值和全局数据结构的值。

工作原理：kprobe可以在运行的内核中动态插入探测点，执行你预定义的操作。用户指定一个探测点，并把一个用户定义的处理函数关联到该探测点, 当内核执行到该探测点时, 相应的关联函数被执行，然后继续执行正常的代码路径。

kprobe 实现了三种类型的探测点：kprobes、jprobes和 kretprobes（也叫返回探测点）。kprobes 是可以被插入到内核的任何指令位置的探测点， jprobes 则只能被插入到一个内核函数的入口，而 kretprobes 则是在指定的内核函数返回时才被执行。

kprobe—[kprobe原理解析（二）](https://www.cnblogs.com/honpey/p/4575902.html)

kprobe—[Linux kprobe调试技术使用](http://www.cnblogs.com/honpey/p/4575928.html)

#### 3.前端工具systemtap

`SystemTap` 是监控和跟踪运行中的 `Linux` 内核的操作的动态方法。这句话的关键词是动态，因为 `SystemTap` 没有使用工具构建一个特殊的内核，而是允许您在运行时动态地安装该工具。它通过一个 `Kprobes` 的应用编程接口 (`API`) 来实现该目的。

但在Systemtap中，用户可以指定原文件，原代码的某一行，或者一个异步事件，探测点处理函数能够立刻输出数据，与printk很类似，它也能查看内核数据。脚本然后被一个翻译器转换成C代码并编译成一个内核模块。生成的C代码编译链接之后生成一个可加载的内核模块。

SystemTap—[在Ubuntu上安装使用Systemtap](https://www.cnblogs.com/wtb2012/p/5218889.html)

SystemTap—[SystemTap使用技巧](https://my.oschina.net/sherrywangzh/blog/1518223)

SystemTap—[SystemTap Language Reference](https://www.sourceware.org/systemtap/langref/)

SystemTap—[SystemTap使用技巧【一】](https://blog.csdn.net/wangzuxi/article/details/42849053)

SystemTap—[SystemTap使用技巧【二】](https://blog.csdn.net/wangzuxi/article/details/42976577)

SystemTap—[SystemTap使用技巧【三】](https://blog.csdn.net/wangzuxi/article/details/43856857)

SystemTap—[SystemTap使用技巧【四】](https://blog.csdn.net/wangzuxi/article/details/44901285)

SystemTap—[systemtap学习总结](https://www.ibm.com/developerworks/cn/linux/l-cn-systemtap3/)

对比：systemtap配置较麻烦，kprobe可以不用重新编译内核就弄清各个函数之间的调用关系。

## 二、ftrace

#### 1.配置

- 编译内核时需配置以下选项：

```bash
$ cat /boot/config-2.6.36 | grep FTRACE
CONFIG_HAVE_FTRACE_NMI_ENTER=y
CONFIG_HAVE_DYNAMIC_FTRACE=y
CONFIG_HAVE_FTRACE_MCOUNT_RECORD=y
CONFIG_FTRACE_NMI_ENTER=y
CONFIG_FTRACE=y                           #FTRACE打开后，编译内核时会打开-pg选项。
CONFIG_FTRACE_SYSCALLS=y
CONFIG_DYNAMIC_FTRACE=y
CONFIG_FTRACE_MCOUNT_RECORD=y
# CONFIG_FTRACE_STARTUP_TEST is not set
```

- 也可以用`make menuconfig`图形化界面来配置：

`Kernel hacking   --->`  —> `Tracers  --->`  —> 可勾选所有。

- 将debugfs编译进内核：

设置`CONFIG_DEBUG_FS=y` 或 `Kernel hacking   --->`  —> `Debug Filesystem`。

**说明**：ftrace通过debugfs向用户态提供访问接口。配置内核时激活debugfs后会创建目录`/sys/kernel/debug`，debug文件系统就是挂载到该目录。

**挂载方式**：在init脚本下加入`mount -t debugfs nodev /sys/kernel/debug`。启动后会创建目录` /sys/kernel/debug/tracing`，改目录下包含ftrace的控制和输出文件。

```bash
/sys/kernel/debug/tracing $ ls
README                      set_event_pid
available_events            set_ftrace_filter
available_filter_functions  set_ftrace_notrace
available_tracers           set_ftrace_pid
buffer_size_kb              set_graph_function
buffer_total_size_kb        set_graph_notrace
current_tracer              snapshot
dyn_ftrace_total_info       stack_max_size
enabled_functions           stack_trace
events                      stack_trace_filter
free_buffer                 trace
function_profile_enabled    trace_clock
instances                   trace_marker
kprobe_events               trace_options
kprobe_profile              trace_pipe
max_graph_depth             trace_stat
options                     tracing_cpumask
per_cpu                     tracing_max_latency
printk_formats              tracing_on
saved_cmdlines              tracing_thresh
saved_cmdlines_size         uprobe_events
set_event                   uprobe_profile
```

#### 2.ftrace数据文件

`/sys/kernel/debug/trace`目录下数据文件的操作，通常使用 echo 命令来修改其值，也可以在程序中通过文件读写相关的函数来操作这些文件的值。

主要文件用途如下：

- **README**文件提供了一个简短的使用说明，展示了 ftrace 的操作命令序列。可以通过 cat 命令查看该文件以了解概要的操作流程。
- **current_tracer**用于设置或显示当前使用的跟踪器；使用 echo 将跟踪器名字写入该文件可以切换到不同的跟踪器。系统启动后，其缺省值为 nop ，即不做任何跟踪操作。在执行完一段跟踪任务后，可以通过向该文件写入 nop 来重置跟踪器。
- **available_tracers**记录了当前编译进内核的跟踪器的列表，可以通过 cat 查看其内容；其包含的跟踪器与图 3 中所激活的选项是对应的。写 current_tracer 文件时用到的跟踪器名字必须在该文件列出的跟踪器名字列表中。
- **trace**文件提供了查看获取到的跟踪信息的接口。可以通过 cat 等命令查看该文件以查看跟踪到的内核活动记录，也可以将其内容保存为记录文件以备后续查看。
- **tracing_enabled**用于控制 current_tracer 中的跟踪器是否可以跟踪内核函数的调用情况。写入 0 会关闭跟踪活动，写入 1 则激活跟踪功能；其缺省值为 1 。
- **set_graph_function**设置要清晰显示调用关系的函数，显示的信息结构类似于 C 语言代码，这样在分析内核运作流程时会更加直观一些。在使用 function_graph 跟踪器时使用；缺省为对所有函数都生成调用关系序列，可以通过写该文件来指定需要特别关注的函数。
- **buffer_size_kb**用于设置单个 CPU 所使用的跟踪缓存的大小。跟踪器会将跟踪到的信息写入缓存，每个 CPU 的跟踪缓存是一样大的。跟踪缓存实现为环形缓冲区的形式，如果跟踪到的信息太多，则旧的信息会被新的跟踪信息覆盖掉。注意，要更改该文件的值需要先将 current_tracer 设置为 nop 才可以。
- **tracing_on**用于控制跟踪的暂停。有时候在观察到某些事件时想暂时关闭跟踪，可以将 0 写入该文件以停止跟踪，这样跟踪缓冲区中比较新的部分是与所关注的事件相关的；写入 1 可以继续跟踪。
- **available_filter_functions**记录了当前可以跟踪的内核函数。对于不在该文件中列出的函数，无法跟踪其活动。
- **set_ftrace_filter**和 **set_ftrace_notrace**在编译内核时配置了动态 ftrace （选中 CONFIG_DYNAMIC_FTRACE 选项）后使用。前者用于显示指定要跟踪的函数，后者则作用相反，用于指定不跟踪的函数。如果一个函数名同时出现在这两个文件中，则这个函数的执行状况不会被跟踪。这些文件还支持简单形式的含有通配符的表达式，这样可以用一个表达式一次指定多个目标函数；具体使用在后续文章中会有描述。注意，要写入这两个文件的函数名必须可以在文件 available_filter_functions 中看到。缺省为可以跟踪所有内核函数，文件 set_ftrace_notrace 的值则为空。

#### 3.ftrace跟踪器类型

可通过`cat available_tracers`查看可用的跟踪器类型。可跟踪的信息如进程调度、中断关闭等。

- **nop**跟踪器不会跟踪任何内核活动，将 nop 写入 current_tracer 文件可以删除之前所使用的跟踪器，并清空之前收集到的跟踪信息，即刷新 trace 文件。
- **function**跟踪器可以跟踪内核函数的执行情况；可以通过文件 set_ftrace_filter 显示指定要跟踪的函数。
- **function_graph**跟踪器可以显示类似 C 源码的函数调用关系图，这样查看起来比较直观一些；可以通过文件 set_grapch_function 显示指定要生成调用流程图的函数。
- **sched_switch**跟踪器可以对内核中的进程调度活动进行跟踪。
- **irqsoff**跟踪器和 **preemptoff**跟踪器分别跟踪关闭中断的代码和禁止进程抢占的代码，并记录关闭的最大时长，**preemptirqsoff**跟踪器则可以看做它们的组合。

ftrace 框架支持扩展添加新的跟踪器，参考[官方开发文档](https://www.kernel.org/doc/Documentation/trace/ftrace-design.txt)可添加自己的跟踪器；参考[官方使用文档](https://www.kernel.org/doc/Documentation/trace/ftrace.txt)学习如何使用ftrace。

#### 4.ftrace使用

步骤如下：

> `$ cd /sys/kernel/debug/tracing/`——切换到目录
>
> `$ cat available_tracers` ——获取可用跟踪器
>
> `$ echo 1 > /proc/sys/kernel/ftrace_enabled`——激活ftrace
>
> 将所选择的跟踪器的名字写入文件 current_tracer。
>
> 将要跟踪的函数写入文件 set_ftrace_filter ，将不希望跟踪的函数写入文件 set_ftrace_notrace。
>
> `$ echo 1 > /proc/sys/kernel/tracing_on`——控制跟踪器的暂停
>
> 查看文件 trace 获取跟踪信息，对内核的运行进行分析调试

##### （1）function跟踪器

```bash
/sys/kernel/debug/tracing $ echo 0 > tracing_on
/sys/kernel/debug/tracing $ echo function > current_tracer 
/sys/kernel/debug/tracing $ echo 1 > tracing_on  #运行一个程序
/sys/kernel/debug/tracing $ echo 0 > tracing_on
/sys/kernel/debug/tracing $ cat trace | heap -20
#
#                              _-----=> irqs-off
#                             / _----=> need-resched
#                            | / _---=> hardirq/softirq
#                            || / _--=> preempt-depth
#                            ||| /     delay
#           TASK-PID   CPU#  ||||    TIMESTAMP  FUNCTION
#              | |       |   ||||       |         |
   reverse_shell-128   [000] ....  5024.031776: eth_type_trans <-loopback_xmit
   reverse_shell-128   [000] ....  5024.031778: netif_rx <-loopback_xmit
   reverse_shell-128   [000] ....  5024.031779: netif_rx_internal <-netif_rx
   reverse_shell-128   [000] ....  5024.031780: enqueue_to_backlog <-netif_rx_internal
   reverse_shell-128   [000] d...  5024.031781: _raw_spin_lock <-enqueue_to_backlog
   reverse_shell-128   [000] d...  5024.031782: __raise_softirq_irqoff <-enqueue_to_backlog
   reverse_shell-128   [000] d...  5024.031783: _raw_spin_unlock <-enqueue_to_backlog
   reverse_shell-128   [000] ....  5024.031785: __local_bh_enable_ip <-__dev_queue_xmit
   reverse_shell-128   [000] ....  5024.031786: __local_bh_enable_ip <-ip_finish_output2

```

##### （2）function_graph跟踪器

function_graph 跟踪器则可以提供类似 C 代码的函数调用关系信息。通过写文件 set_graph_function 可以显示指定要生成调用关系的函数，缺省会对所有可跟踪的内核函数生成函数调用关系图。如下，将内核函数 __do_fault 作为观察对象。

```bash
/sys/kernel/debug/tracing $ echo 0 > /proc/sys/kernel/ftrace_enabled 
/sys/kernel/debug/tracing $ echo 0 > tracing_on
/sys/kernel/debug/tracing $ echo function_graph > current_tracer 
/sys/kernel/debug/tracing $ echo __do_fault > set_graph_function
/sys/kernel/debug/tracing $ echo 1 > /proc/sys/kernel/ftrace_enabled
/sys/kernel/debug/tracing $ echo 1 > tracing_on
/sys/kernel/debug/tracing $ echo 0 > tracing_on
/sys/kernel/debug/tracing $ cat trace | head -20
# tracer: function_graph
#
# CPU  DURATION                  FUNCTION CALLS
# |     |   |                     |   |   |   |
 0)   0.471 us    |                            } /* __compute_runnable_contrib */
 0)   0.929 us    |                            account_entity_enqueue();
 0)   1.501 us    |                            update_cfs_shares();
 0)   0.499 us    |                            place_entity();
 0)   0.539 us    |                            __enqueue_entity();
 0) + 26.142 us   |                          } /* enqueue_entity */
 0)               |                          enqueue_entity() {
 0)               |                            update_curr() {
 0)   0.754 us    |                              update_min_vruntime();
 0)   0.889 us    |                              cpuacct_charge();
 0)   8.973 us    |                            }
 0)   0.398 us    |                            __compute_runnable_contrib();
 0)   0.478 us    |                            account_entity_enqueue();
 0)   0.580 us    |                            update_cfs_shares();
 0)   0.412 us    |                            place_entity();
 0)   0.411 us    |                            __enqueue_entity();
/sys/kernel/debug/tracing # echo > set_graph_function
```

CPU 字段给出了执行函数的 CPU 号，本例中都为 0 号 CPU。DURATION 字段给出了函数执行的时间长度，以 us 为单位。FUNCTION CALLS 则给出了调用的函数，并显示了调用流程。注意，对于不调用其它函数的函数，其对应行以“;”结尾，而且对应的 DURATION 字段给出其运行时长；对于调用其它函数的函数，则在其“}”对应行给出了运行时长，该时间是一个累加值，包括了其内部调用的函数的执行时长。DURATION 字段给出的时长并不是精确的，它还包含了执行 ftrace 自身的代码所耗费的时间，所以示例中将内部函数时长累加得到的结果会与对应的外围调用函数的执行时长并不一致；不过通过该字段还是可以大致了解函数在时间上的运行开销的。最后通过 echo 命令重置了文件 set_graph_function 。

##### （3）sched_switch 跟踪器

sched_switch 跟踪器可以对进程的调度切换以及之间的唤醒操作进行跟踪。

```bash
[root@linux tracing]$ echo 1 > /proc/sys/kernel/ftrace_enabled 
[root@linux tracing]$ echo 0 > tracing_on 
[root@linux tracing]$ echo sched_switch > current_tracer 
[root@linux tracing]$ echo 1 > tracing_on 
# 运行一段时间，使ftrace收集一些跟踪信息。
[root@linux tracing]$ echo 0 > tracing_on
[root@linux tracing]$ cat trace | head -10 
# tracer: sched_switch 
# 
#  TASK-PID    CPU#    TIMESTAMP  FUNCTION 
#     | |       |          |         | 
     bash-1408  [000] 26208.816058:   1408:120:S   + [000]  1408:120:S bash 
     bash-1408  [000] 26208.816070:   1408:120:S   + [000]  1408:120:S bash 
     bash-1408  [000] 26208.816921:   1408:120:R   + [000]     9:120:R events/0 
     bash-1408  [000] 26208.816939:   1408:120:R ==> [000]     9:120:R events/0 
 events/0-9     [000] 26208.817081:      9:120:R   + [000]  1377:120:R gnome-terminal
 events/0-9     [000] 26208.817088:      9:120:S ==> [000]  1377:120:R gnome-terminal
```

进程间的唤醒操作和调度切换信息，可以通过符号‘ + ’和‘ ==> ’区分。描述进程状态的格式为“Task-PID:Priority:Task-State”。以示例跟踪信息中的第一条跟踪记录为例，可以看到进程 bash 的 PID 为 1408 ，其对应的内核态优先级为 120 ，当前状态为 S（可中断睡眠状态），当前 bash 并没有唤醒其它进程；从第 3 条记录可以看到，进程 bash 将进程 events/0 唤醒，而在第 4 条记录中发生了进程调度，进程 bash 切换到进程 events/0 执行。

在 Linux 内核中，进程的状态在内核头文件 include/linux/sched.h 中定义，包括可运行状态 TASK_RUNNING（对应跟踪信息中的符号‘ R ’）、可中断阻塞状态 TASK_INTERRUPTIBLE（对应跟踪信息中的符号‘ S ’）等。同时该头文件也定义了用户态进程所使用的优先级的范围，最小值为 MAX_USER_RT_PRIO（值为 100 ），最大值为 MAX_PRIO - 1（对应值为 139 ），缺省为 DEFAULT_PRIO（值为 120 ）；在本例中，进程优先级都是缺省值 120 。

##### （4）irqsoff 跟踪器

[详细说明](https://www.ibm.com/developerworks/cn/linux/l-cn-ftrace2/)

irqsoff 跟踪器可以对中断被关闭的状况进行跟踪，有助于发现导致较大延迟的代码；当出现最大延迟时，跟踪器会记录导致延迟的跟踪信息，文件 tracing_max_latency 则记录中断被关闭的最大延时。

```bash
[root@linux tracing]# echo irqsoff > current_tracer
```

##### （5）跟踪指定模块中的函数

可使用简单格式的通配符（用单引号括起来）：

- **begin\***选择所有名字以 begin 字串开头的函数
- ***middle\***选择所有名字中包含 middle 字串的函数
- **\*end**选择所有名字以 end 字串结尾的函数

指定属于特定模块的函数，用mod指令：

```bash
$ echo ':mod:[module_name]' > set_ftrace_filter
#Eg，指定跟踪模块 ipv6 中的函数
$ echo ':mod:ipv6' > set_ftrace_filter 
#Eg，跟踪ext3模块中write开头的函数
$ echo 'write*:mod:ext3' > set_ftrace_filter
#Eg，排除ext3模块中write开头的函数，用"!"
$ echo '!writeback*:mod:ext3' >> set_ftrace_filter
```

#### 5. 在代码中使用ftrace

##### （1）trace_printk——打印跟踪信息

简介：使用方式与 printk() 类似，用于向 ftrace 跟踪缓冲区输出跟踪信息。配置`CONFIG_TRACING`选项后就会定义`trace_printk()`宏（见`include/linux/kernel.h`）。

理解：就是在内核代码中嵌入trace_printk()语句，这样在用ftrace的`function_graph`跟踪器对内核进行监控时就能在trace文件中看到trace_printk()输出的信息。

例如示例模块**`ftrace_demo`**：

```c
/*                                                     
* ftrace_demo.c 
*/                                                    
#include <linux/init.h> 
#include <linux/module.h> 
#include <linux/kernel.h> 
 
MODULE_LICENSE("GPL"); 
 
static int ftrace_demo_init(void) 
{ 
    trace_printk("Can not see this in trace unless loaded for the second time\n"); 
    return 0; 
} 
 
static void ftrace_demo_exit(void) 
{ 
    trace_printk("Module unloading\n"); 
} 
 
module_init(ftrace_demo_init); 
module_exit(ftrace_demo_exit);
```

对模块`ftrace_demo`进行**跟踪**：

```bash
[root@linux tracing]$ echo 1 > /proc/sys/kernel/ftrace_enabled 
[root@linux tracing]$ echo function_graph > current_tracer 
# 事先加载模块 ftrace_demo (加载后才能在写文件 set_ftrace_filter 时找到该模块)
 
[root@linux tracing]$ echo ':mod:ftrace_demo' > set_ftrace_filter 
[root@linux tracing]$ cat set_ftrace_filter 
ftrace_demo_init 
ftrace_demo_exit 
 
# 将模块 ftrace_demo 卸载
 
[root@linux tracing]$ echo 1 > tracing_enabled 
 
# 重新进行模块 ftrace_demo 的加载与卸载操作
 
[root@linux tracing]# cat trace 
# tracer: function_graph 
# 
# CPU  DURATION                  FUNCTION CALLS 
# |     |   |                     |   |   |   | 
1)               |  /* Can not see this in trace unless loaded for the second time */ 
0)               |  /* Module unloading */
```

##### （2）tracing_on/tracing_off —— 控制跟踪信息的记录

代码中，可以利用tracing_on() 和 tracing_off()来继续和暂停跟踪，类似于对 /sys/kernel/debug/tracing 下的文件 tracing_on 分别执行写 1 和 写 0 的操作（前者节省上下文切换、系统调度控制等的时间）。

使用 tracing_off 的模块 ftrace_demo：

```c
/*                                                     
* ftrace_demo.c 
*     modified to demostrate the usage of tracing_off 
*/                                                    
#include <linux/init.h> 
#include <linux/module.h> 
#include <linux/kernel.h> 
 
MODULE_LICENSE("GPL"); 
 
static int ftrace_demo_init(void) 
{      
    trace_printk("ftrace_demo_init called\n"); 
    tracing_off(); 
    return 0; 
} 
 
static void ftrace_demo_exit(void) 
{ 
    trace_printk("ftrace_demo_exit called\n"); 
    tracing_off(); 
} 
 
module_init(ftrace_demo_init); 
module_exit(ftrace_demo_exit);
```

**跟踪**：

```bash
[root@linux tracing]$ echo 1 > /proc/sys/kernel/ftrace_enabled 
[root@linux tracing]$ echo 1 > tracing_on 
[root@linux tracing]$ echo function > current_tracer 
[root@linux tracing]$ echo 1 > tracing_enabled 
 
# 加载模块 ftrace_demo，模块初始化函数 ftrace_demo_init 被调用
 
[root@linux tracing]$ cat tracing_on 
0 
[root@linux tracing]$ cat trace | wc -l 
120210 
[root@linux tracing]$ cat trace | grep -n ftrace_demo_init 
120187:      insmod-2897  [000]  2610.504611: ftrace_demo_init <-do_one_initcall 
120193:      insmod-2897  [000]  2610.504667: ftrace_demo_init: ftrace_demo_init called 
 
[root@linux tracing]$ echo 1 > tracing_on   # 继续跟踪信息的记录
 
# 卸载模块 ftrace_demo，模块函数 ftrace_demo_exit 被调用
 
[root@linux tracing]$ cat tracing_on 
0 
[root@linux tracing]$ wc -l trace 
120106 trace 
[root@linux tracing]$ grep -n ftrace_demo_exit trace 
120106:           rmmod-2992  [001]  3016.884449: : ftrace_demo_exit called
```

**优点**：在代码中使用 tracing_off() 可以控制将感兴趣的信息保存在跟踪缓冲区的末端位置，不会很快被新的信息所覆盖，便于及时查看。还可以通过特定条件（比如检测到某种异常状况，等等）来控制跟踪信息的记录，如下所示。实践中，可以通过宏来控制是否将对这些函数的调用编译进内核模块，这样可以在调试时将其开启，在最终发布时将其关闭。**用户态的应用程序**可以通过直接读写文件 tracing_on 来控制记录跟踪信息的暂停状态，以便了解应用程序运行期间内核中发生的活动。

```c
if (condition) 
    tracing_on() or tracing_off()
```

**总结**：ftrace能有效监测内核活动、函数调用，但是无法获取调用参数、调用上下文、甚至修改上下文。不过可以利用该机制往源码插入代码（如trace_printfk，输出调用参数），然后动态监测。如果要开发代码去监测内核，参考`/kernel/trace/ftrace.c`[代码](https://elixir.bootlin.com/linux/v3.4.110/source/kernel/trace/ftrace.c)，编写hook内核API的代码请参考以下文章和代码。

[示例代码](https://github.com/ilammy/ftrace-hook)

[Hooking linux内核函数（一）：寻找完美解决方案](https://xz.aliyun.com/t/2947)

[Hooking linux内核函数（二）：如何使用Ftrace hook函数](https://xz.aliyun.com/t/2948)

[Hooking linux内核函数（三）：Ftrace的主要优缺点](https://xz.aliyun.com/t/2949)

---

## 三、Kprobes

探测手段：3种，kprobe、jprobe和kretprobe。

使用方式：2种，第一种是编写内核模块，向内核注册探测点，自定义回调函数；第二种是使用kprobes in ftrace，这种方式结合kprobe和ftrace，可以通过kprobe来优化ftrace跟踪函数。

#### 1.编写kprobe探测模块

##### （1）struct kprobe结构体

```c
// kprobe结构表示一个探测点
struct kprobe {
    struct hlist_node hlist;// 被用于kprobe全局hash，索引值为被探测点的地址。
    struct list_head list;  // 用于链接同一被探测点的不同探测kprobe。
    /*count the number of times this probe was temporarily disarmed */
    unsigned long nmissed;
    kprobe_opcode_t *addr;  // 被探测点的地址。
    const char *symbol_name;// 被探测函数的名称。
    unsigned int offset;    // 被探测点在函数内部的偏移，用于探测函数内核的指令，如果该值为0表示函数的入口。
    kprobe_pre_handler_t pre_handler;    // 被探测点指令执行之前调用的回调函数。
    kprobe_post_handler_t post_handler;  // 被探测点指令执行之后调用的回调函数。
    kprobe_fault_handler_t fault_handler;// 在执行pre_handler、post_handler或单步执行被探测指令时出现内存异常则会调用该回调函数。
    kprobe_break_handler_t break_handler;// 在执行某一kprobe过程中触发了断点指令后会调用该函数，用于实现jprobe。
    kprobe_opcode_t opcode;              // 保存的被探测点原始指令。
    struct arch_specific_insn ainsn;     // 被复制的被探测点的原始指令，用于单步执行，架构强相关。
    u32 flags;                           // 状态标记。
};
```

##### （2）kprobe API函数

```c
int register_kprobe(struct kprobe *p);                // 注册kprobe探测点
void unregister_kprobe(struct kprobe *p);             // 卸载kprobe探测点
int register_kprobes(struct kprobe **kps, int num);   // 注册多个kprobe探测点
void unregister_kprobes(struct kprobe **kps, int num);// 卸载多个kprobe探测点
int disable_kprobe(struct kprobe *kp);                // 暂停指定kprobe探测点
int enable_kprobe(struct kprobe *kp);                 // 恢复指定kprobe探测点
void dump_kprobe(struct kprobe *kp);                  // 打印指定kprobe探测点的名称、地址、偏移
```

##### （3）kprobe_example.c 示例

示例代码见`/samples/kprobes/kprobe_example.c`，介绍如何使用kprobe。探测目标是`_do_fork`，该函数会在fork系统调用或者kernel_kthread创建内核线程时被调用。

```c
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
```

模块的编译Makefile如下：

```bash
obj-m := kprobe_example.o

CROSS_COMPILE=''
#KDIR := /lib/modules/$(shell uname -r)/build
KDIR := /home/john/Desktop/stringIPC/linux-4.4.184
all:
	make -C $(KDIR) M=$(PWD) modules 
clean:
	rm -f *.ko *.o *.mod.o *.mod.c .*.cmd *.symvers  modul*
```

insmod加载，等待后rmmod卸载，执行结果如下：

```bash
$ dmesg
[   13.365009] Planted kprobe at _do_fork+0x0/0x360
[   20.849401] <_do_fork> pre_handler: p->addr = _do_fork+0x0/0x360, ip = ffffffff81083471, flags = 0x246
[   20.849458] <_do_fork> post_handler: p->addr = _do_fork+0x0/0x360, flags = 0x246
[   52.741703] <_do_fork> pre_handler: p->addr = _do_fork+0x0/0x360, ip = ffffffff81083471, flags = 0x246
[   52.741747] <_do_fork> post_handler: p->addr = _do_fork+0x0/0x360, flags = 0x246
[   73.833422] <_do_fork> pre_handler: p->addr = _do_fork+0x0/0x360, ip = ffffffff81083471, flags = 0x246
[   73.833465] <_do_fork> post_handler: p->addr = _do_fork+0x0/0x360, flags = 0x246
[   73.866238] kprobe at _do_fork+0x0/0x360 unregistered
$ cat /proc/kallsyms | grep _do_fork  
ffffffff81083470 T _do_fork
# 验证后发现地址和符号是对应的
```

#### 2.基于ftrace使用kprobe

##### （1）kprobe配置

`make menuconfig` 设置"Kernel hacking"->"Tracers"->"Enable kprobes-based dynamic events"。我看默认是设置的。

```c
CONFIG_KPROBES=y
CONFIG_OPTPROBES=y
CONFIG_KPROBES_ON_FTRACE=y
CONFIG_UPROBES=y
CONFIG_KRETPROBES=y
CONFIG_HAVE_KPROBES=y
CONFIG_HAVE_KRETPROBES=y
CONFIG_HAVE_OPTPROBES=y
CONFIG_HAVE_KPROBES_ON_FTRACE=y
CONFIG_KPROBE_EVENT=y
```

挂载debugfs步骤和配置ftrace一样：`mount -t debugfs nodev /sys/kernel/debug`。

##### （2）probe trace events使用

配置后能在`/sys/kernel/debug/tracing/`目录下看到相应文件：

```c
/sys/kernel/debug/tracing/kprobe_events								  // 配置kprobe事件属性，增加事件之后会在kprobes下面生成对应目录。
/sys/kernel/debug/tracing/kprobe_profile                // kprobe事件统计属性文件。
/sys/kernel/debug/tracing/kprobes/<GRP>/<EVENT>/enabled // 使能kprobe事件
/sys/kernel/debug/tracing/kprobes/<GRP>/<EVENT>/filter  // 过滤kprobe事件
/sys/kernel/debug/tracing/kprobes/<GRP>/<EVENT>/format  // 查询kprobe事件显示格式
```

**新增kprobe事件**：通过写`kprobe_event`来设置然后在`/sys/kernel/debug/tracing/trace`中看结果。

```c
p[:[GRP/]EVENT] [MOD:]SYM[+offs]|MEMADDR [FETCHARGS] // 设置一个probe探测点
r[:[GRP/]EVENT] [MOD:]SYM[+0] [FETCHARGS]            // 设置一个return probe探测点
-:[GRP/]EVENT																				 // 删除一个探测点
```

```c
// 具体解释：
GRP        : Group name. If omitted, use "kprobes" for it. // 设置后会在events/kprobes下创建<GRP>目录。
 EVENT        : Event name. If omitted, the event name is generated based on SYM+offs or MEMADDR. // 指定后在events/kprobes/<GRP>生成<EVENT>目录。
 MOD        : Module name which has given SYM.                // 模块名，一般不设
 SYM[+offs]    : Symbol+offset where the probe is inserted.   // 被探测函数名和偏移
 MEMADDR    : Address where the probe is inserted.            // 指定被探测的内存绝对地址
 FETCHARGS    : Arguments. Each probe can have up to 128 args.// 指定要获取的参数信息。
 %REG        : Fetch register REG                             // 获取指定寄存器值
 @ADDR        : Fetch memory at ADDR (ADDR should be in kernel)// 获取指定内存地址的值
 @SYM[+|-offs]    : Fetch memory at SYM +|- offs (SYM should be a data symbol)// 获取全局变量的值
 $stackN    : Fetch Nth entry of stack (N >= 0)        // 获取指定栈空间值，即sp寄存器+N后的位置值
 $stack    : Fetch stack address.                      // 获取sp寄存器值
 $retval    : Fetch return value.(*)                   // 获取返回值，用户return kprobe
 $comm        : Fetch current task comm.               // 获取对应进程名称。
 +|-offs(FETCHARG) : Fetch memory at FETCHARG +|- offs address.(**)
 NAME=FETCHARG : Set NAME as the argument name of FETCHARG.
 FETCHARG:TYPE : Set TYPE as the type of FETCHARG. Currently, basic types (u8/u16/u32/u64/s8/s16/s32/s64), hexadecimal types
          (x8/x16/x32/x64), "string" and bitfield are supported. // 设置参数的类型，可以支持字符串和比特类型
  (*) only for return probe.
  (**) this is useful for fetching a field of data structures. 
```

执行如下两条命令就会生成目录/sys/kernel/debug/tracing/events/kprobes/myprobe；第三条命令则可以删除指定kprobe事件，如果要全部删除则echo > /sys/kernel/debug/tracing/kprobe_events。

```bash
$ echo 'p:myprobe do_sys_open dfd=%ax filename=%dx flags=%cx mode=+4($stack)' > /sys/kernel/debug/tracing/kprobe_events
$ echo 'r:myretprobe do_sys_open ret=$retval' >> /sys/kernel/debug/tracing/kprobe_events #这里面一定要用">>"，不然就会覆盖前面的设置。

$ echo '-:myprobe' >> /sys/kernel/debug/tracing/kprobe_events
$ echo '-:myretprobe' >> /sys/kernel/debug/tracing/kprobe_events
```

参数后面的寄存器是跟架构相关的，%ax、%dx、%cx表示第1/2/3个参数，超出部分使用$stack来存储参数。

函数返回值保存在$retval中。

**kprobe使能**：对kprobe事件的是能通过往对应事件的enable写1开启探测；写0暂停探测。`/sys/kernel/debug/tracing/events/kprobes/myprobe/enable`

```bash
$ echo > /sys/kernel/debug/tracing/trace
$ echo 'p:myprobe do_sys_open dfd=%ax filename=%dx flags=%cx mode=+4($stack)' > /sys/kernel/debug/tracing/kprobe_events
$ echo 'r:myretprobe do_sys_open ret=$retval' >> /sys/kernel/debug/tracing/kprobe_events

$ echo 1 > /sys/kernel/debug/tracing/events/kprobes/myprobe/enable
$ echo 1 > /sys/kernel/debug/tracing/events/kprobes/myretprobe/enable
$ ls
$ echo 0 > /sys/kernel/debug/tracing/events/kprobes/myprobe/enable
$ echo 0 > /sys/kernel/debug/tracing/events/kprobes/myretprobe/enable

$ cat /sys/kernel/debug/tracing/trace
						sourceinsight4.-3356  [000] .... 3542865.754536: myprobe: (do_sys_open+0x0/0x290) dfd=0xffffffffbd6764a0 filename=0x8000 flags=0x1b6 mode=0xe3afff48ffffffff
            bash-26041 [001] .... 3542865.757014: myprobe: (do_sys_open+0x0/0x290) dfd=0xffffffffbd676460 filename=0x8241 flags=0x1b6 mode=0xe0c0ff48ffffffff
              ls-18078 [005] .... 3542865.757950: myprobe: (do_sys_open+0x0/0x290) dfd=0xffffffffbd676460 filename=0x88000 flags=0x1 mode=0xc1b7bf48ffffffff
              ls-18078 [005] d... 3542865.757953: myretprobe: (SyS_open+0x1e/0x20 <- do_sys_open) ret=0x3
              ls-18078 [005] .... 3542865.757966: myprobe: (do_sys_open+0x0/0x290) dfd=0xffffffffbd676460 filename=0x88000 flags=0x6168 mode=0xc1b7bf48ffffffff
```

##### （3）kprobe事件过滤

利用写filter进行过滤（`/sys/kernel/debug/tracing/events/kprobes/myprobe/filter`）。它支持的格式和c语言的表达式类似，支持 ==，!=，>，<，>=，<=判断，并且支持与&&，或||，还有()。

```bash
$ echo 'filename==0x8241' > /sys/kernel/debug/tracing/events/kprobes/myprobe/filter
```

##### （4）kprobe和栈配合使用

可以在现实函数的同事显示其栈信息，通过配置trace_options。

```bash
$ echo stacktrace > /sys/kernel/debug/tracing/trace_options
```

##### （5）kprobe_profile统计信息

后面两列分别表示命中和未命中的次数。

```bash
$ cat /sys/kernel/debug/tracing/kprobe_profile 
  myprobe                                                   11               0
  myretprobe                                                11               0
```

kprobe源码分析可参考《[Linux内核调试技术——kprobe使用与实现](https://blog.csdn.net/luckyapple1028/article/details/52972315)》第四节《四、kprobe实现源码分析》。

#### 3.kprobe问题

**问题**：据说是能够修改寄存器和数据结构，但是没有找到修改方法。

追踪内核栈及其他数据请参考代码**[kprobe-tracer](https://github.com/evelinad/kprobe-tracer)**和**[RBTree_Kprobe_LinuxKernel](https://github.com/kushal2490/RBTree_Kprobe_LinuxKernel)**。

---

## 四、SystemTap

#### 1.配置

自动化安装请参考[自动化脚本](https://github.com/tatumsu/study/tree/63354f3536ececc23214e0d8de45bff56ee72cb2/systemtap)，执行`sudo ./install_all.sh`即可（注意缺`generate_ko.sh`文件）。

##### （1）安装systemtap

**apt-get**：`sudo apt-get install elfutils libcap-dev systemtap`

**卸载**：`sudo apt-get remove systemtap`

**源码安装**：[下载链接](https://sourceware.org/systemtap/ftp/releases/)	

> ./configure
> make
> sudo make instal

**卸载**：`sudo make uninstall`

##### （2）安装debug symbols

使用方式：2种，第一种是编写内核模块，向内核注册探测点，探测函数根据需要自行定制，但是使用不方便；第二种是使用kprobes in ftrace，这种方式结合kprobe和ftrace，可以通过kprobe来优化ftrace跟踪函数。

```bash
# 配置ddeb repository
$ sudo cat > /etc/apt/sources.list.d/ddebs.list << EOF
$ deb http://ddebs.ubuntu.com/ precise main restricted universe multiverse
EOF

$ sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys ECDCAD72428D7C01
$ sudo apt-get update
# 下载和你当前内核版本相对应的debug symbols —— 使用一个写的很好的脚本
$ wget http://www.domaigne.com/download/tools/get-dbgsym
$ chmod +x get-dbgsym
$ sudo ./get-dbgsy
```

##### （3）生成systemtap/libelf所需的模块信息

将如下命令放入generate_ko.sh：

```bash
for file in `find /usr/lib/debug -name '*.ko' -print`
do
        buildid=`eu-readelf -n $file| grep Build.ID: | awk '{print $3}'`
        dir=`echo $buildid | cut -c1-2`
        fn=`echo $buildid | cut -c3-`
        mkdir -p /usr/lib/debug/.build-id/$dir
        ln -s $file /usr/lib/debug/.build-id/$dir/$fn
        ln -s $file /usr/lib/debug/.build-id/$dir/${fn}.debug
done
```

然后执行该文件：`$ sudo ./generate_ko.sh`

##### （4）安装成功

输入以下命令，若打印“hello world”则安装成功。

```bash
$ stap -e 'probe kernel.function("sys_open") {log("hello world") exit()}'
```

若报错如下：

```c
stap: Symbol `SSL_ImplementedCiphers' has different size in shared object, consider re-linking
In file included from include/linux/mutex.h:15:0,
                 from /tmp/staphH2yQD/stap_6e022ad97cbe9c6f46b582f7a0eac81d_1242_src.c:25:
include/linux/spinlock_types.h:55:14: error: ‘__ARCH_SPIN_LOCK_UNLOCKED’ undeclared here (not in a function)
```

说明有些共享库需要重新readlink，执行如下命令：

```bash
$ readlink /lib/modules/`uname -r`/build/
```

#### 2.SystemTap使用

SystemTap—[SystemTap官方语法](https://www.sourceware.org/systemtap/langref/)

SystemTap—[SystemTap官方示例](https://sourceware.org/systemtap/wiki/WarStories)

##### （1）stap命令

```bash
stap [OPTIONS] FILENAME [ARGUMENTS]
stap [OPTIONS] - [ARGUMENTS]
stap [OPTIONS] –e SCRIPT [ARGUMENTS]

比较常用和有用的参数：
-e SCRIPT               # 运行脚本
-l PROBE                # 列出匹配的探针
-L PROBE                # 列出匹配的探针和局部变量
-g                      # guru mode 
-D NM=VAL               # 向生成的c代码注入宏定义
-o FILE                 # 脚本输出到文件，而非stdout
-x PID                  # 设置 target() 到 PID
```

##### （2）脚本语法

**probe探针用法**：

```c
// probe probe-point { statement }
// 在Hello World例子中begin和end就是probe-point， statement就是该探测点的处理逻辑，在Hello World例子中statement只有一行print，statement可以是复杂的代码块。
begin                          // 在脚本开始时触发
end                            // 在脚本结束时触发
kernel.function(PATTERN)       // 在命名函数执行时触发
kernel.function(PATTERN).call  // 同上
kernel.function(PATTERN).return// 在命名函数返回时触发
kernel.function(PATTERN).return.maxactive(VALUE)
kernel.syscall.*               // 进行任何系统调用时触发
kernel.function(PATTERN).inline
kernel.function(PATTERN).label(LPATTERN)
module(MPATTERN).function(PATTERN)
module(MPATTERN).function(PATTERN).call
module(MPATTERN).function(PATTERN).return.maxactive(VALUE)
module(MPATTERN).function(PATTERN).inline
kernel.statement(PATTERN)     // 使探针探测到确切的代码行
kernel.statement(ADDRESS).absolute
module(MPATTERN).statement(PATTERN)
process(PROCESSPATH).function(PATTERN)
process(PROCESSPATH).function(PATTERN).call
process(PROCESSPATH).function(PATTERN).return
process(PROCESSPATH).function(PATTERN).inline
process(PROCESSPATH).statement(PATTERN)
```

**PATTERN语法**：

```c
// 语法格式： 3部分——函数名字 + @ + 源文件路径 + (":"——绝对行号；"+"——函数入口相对行号)
func[@file]
func@file:linenumber
// Eg：
kernel.function("*init*")
kernel.function(“*@kernel/fork.c:934”)   // 到达 fork.c 的第 934 行时触发
module("ext3").function("*")             // 调用 ext3 模块中任何函数时触发
kernel.statement("*@kernel/time.c:296")  //
kernel.statement("bio_init@fs/bio.c+3")  // 引用文件fs/bio.c 内bio_init+3 这一行语句
process("/home/admin/tengine/bin/nginx").function("ngx_http_process_request")
timer.jiffies(1000)                      // 每隔 1000 个内核 jiffy 触发一次
timer.ms(200).randomize(50)              // 每隔 200 毫秒触发一次，带有线性分布的随机附加时间（-50 到 +50）
```

**基本语法**：与C语言类似，只是每一行结尾";"是可选的。主要语句如下： if/else、while、for/foreach、break/continue、return、next、delete、try/catch 其中： next：主要在probe探测点逻辑处理中使用，调用此语句时，立刻从调用函数中退出。不同于exit()的是，执行到next语句时，会马上从探测点处理函数中返回，而此SystemTap并没有终止，但exit()则会终止SystemTap。

**变量**：不需要明确声明变量类型，用”global“声明的变量（使用过多会有性能损失），获取进程中的变量（全局变量、局部变量、参数）直接在变量名前面加$即可（后面会有例子）。

**函数**：

```c
function indent:string (delta:long){
  return _generic_indent(-1, "",  delta)
}

function _generic_indent (idx, desc, delta)
{
  ts = __indent_timestamp ()
  if (! _indent_counters[idx]) _indent_timestamps[idx] = ts
  depth = _generic_indent_depth(idx, delta)
  return sprintf("%6d (%d:%d) %s:%-*s", (ts - _indent_timestamps[idx]), depth, delta, desc, depth, "")
}  

function strlen:long(s:string) %{
    STAP_RETURN(strlen(STAP_ARG_s));
%}
```

**获取stap命令行参数**：

脚本example.stp：`probe begin { printf(“%d, %s/n”, $1, @2) }`

命令：`$ stap example.stp 10 mystring`

$1 会被替换成10 ，而@2 会被替换成”mystring” ，结果输出：`10, mystring`

#### 3.SystemTap使用技巧

请参考[【linux内核调试】SystemTap使用技巧](https://blog.csdn.net/panhewu9919/article/details/103113711)

#### 4.讨论

优点：可以很方便的修改变量和参数。

缺点：如何安装到定制的内核中，放到qemu中运行（如何给镜像安装debug symbols）？



## 参考：

[Linux内核调试的方式以及工具集锦](https://blog.csdn.net/gatieme/article/details/68948080)

ftrace—[使用ftrace学习linux内核函数调用](https://www.cnblogs.com/zengkefu/p/6349658.html)

ftrace—[ftrace：跟踪你的内核函数！](https://linux.cn/article-9273-1.html)

ftrace—[使用ftrace调试Linux内核，第1部分](https://www.ibm.com/developerworks/cn/linux/l-cn-ftrace1/index.html)

ftrace—[使用ftrace调试Linux内核，第2部分](https://www.ibm.com/developerworks/cn/linux/l-cn-ftrace2/)

ftrace—[使用ftrace调试Linux内核，第3部分](https://www.ibm.com/developerworks/cn/linux/l-cn-ftrace3/)

ftrace—[ftrace官方文档](https://www.kernel.org/doc/Documentation/trace/ftrace.txt)

kprobe—[kprobe原理解析（二）](https://www.cnblogs.com/honpey/p/4575902.html)

kprobe—[Linux kprobe调试技术使用](https://www.cnblogs.com/arnoldlu/p/9752061.html)

SystemTap—[在Ubuntu上安装使用Systemtap](https://www.cnblogs.com/wtb2012/p/5218889.html)

SystemTap—[SystemTap使用技巧](https://my.oschina.net/sherrywangzh/blog/1518223)

SystemTap—[SystemTap Language Reference](https://www.sourceware.org/systemtap/langref/)

SystemTap—[SystemTap使用技巧【一】](https://blog.csdn.net/wangzuxi/article/details/42849053)

SystemTap—[SystemTap使用技巧【二】](https://blog.csdn.net/wangzuxi/article/details/42976577)

SystemTap—[SystemTap使用技巧【三】](https://blog.csdn.net/wangzuxi/article/details/43856857)

SystemTap—[SystemTap使用技巧【四】](https://blog.csdn.net/wangzuxi/article/details/44901285)

SystemTap—[systemtap学习总结](https://klwork.com/category/018linux/systemtap.html)

