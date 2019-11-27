# 【linux内核调试】SystemTap使用技巧

SystemTap配置、内核调试方法对比请参考[【linux内核调试】内核调试方法对比](https://www.jianshu.com/p/285c91c97c28)

### 1.SystemTap使用技巧

##### （1）定位函数位置——`-l`

定位内核系统调用函数在哪个文件上，以往是用source insight或者grep找：

```bash
$ grep -nr 'SYSCALL_DEFINE3(open' ./ 
./fs/compat.c:1075:COMPAT_SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, umode_t, mode) 
./fs/compat.c:1461:COMPAT_SYSCALL_DEFINE3(open_by_handle_at, int, mountdirfd, 
./fs/open.c:1011:SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, umode_t, mode) 
./fs/fhandle.c:254:SYSCALL_DEFINE3(open_by_handle_at, int, mountdirfd,
```

而SystemTap找的更准确：

```bash
$ stap -l 'kernel.function("sys_open")' 
kernel.function("SyS_open@/build/buildd/linux-lts-trusty-3.13.0/fs/open.c:1011")
# 可以找某个进程中的函数
$ stap -l 'process("/lib/x86_64-linux-gnu/libc.so.6").function("printf")' 
process("/lib/x86_64-linux-gnu/libc-2.15.so").function("__printf@/build/buildd/eglibc-2.15/stdio-common/printf.c:29")
# 可以*号来模糊查找
$ stap -l 'kernel.function("*recv")'
# 可以查看是哪个宏定义编译的版本
$ stap -l 'process("/home/admin/tengine/bin/nginx").function("ngx_shm_alloc")'
process("/home/admin/tengine/bin/nginx").function("ngx_shm_alloc@src/os/unix/ngx_shmem.c:15")
```

##### （2）查看可用探测点及探测点上的可用变量——`-L`

可用`-L`参数来看看有哪些变量可直接使用，注意被编译器优化掉的变量就获取不到了。

```bash
# 可见，在该探测点上可直接用$shm变量，类型是ngx_shm_t*。
$ stap -L 'process("/home/admin/tengine/bin/nginx").function("ngx_shm_alloc")' 
process("/home/admin/tengine/bin/nginx").function("ngx_shm_alloc@src/os/unix/ngx_shmem.c:15") $shm:ngx_shm_t*
# statement类似
$ stap -L 'process("/home/admin/tengine/bin/nginx").statement("ngx_pcalloc@src/core/ngx_palloc.c:*")' 
```

##### （3）输出调用堆栈

查看调用栈回溯。

用户态探测点堆栈：`print_ubacktrace()`、`sprint_ubacktrace()` 内核态探测点堆栈：`print_backtrace()`、`sprint_backtrace()` 不带s和带s的区别是前者直接输出，后者是返回堆栈字符串。

```bash
# 例如，查看tengine返回5xx时的调用堆栈是怎样的：
$ cat debug_tengine_5xx.stp 
probe process("/home/admin/tengine/bin/nginx").function("ngx_http_finalize_request").call {
    if ($rc >= 500) {
        printf("rc: %d\n", $rc)
        print_ubacktrace()
    }
}
$ stap debug_tengine_5xx.stp 
rc: 502
 0x49af2e : ngx_http_finalize_request+0xe/0x480 [/home/admin/tengine/bin/nginx]
 0x543305 : ngx_http_video_flv_send_rest+0xf5/0x380 [/home/admin/tengine/bin/nginx]
 0x45a740 : main+0xa90/0xb50 [/home/admin/tengine/bin/nginx]
 0x3623e1ecdd [/lib64/libc-2.12.so+0x1ecdd/0x38d000]
# 例如，查看内核收包：
$ cat netif_receive_skb.stp 
probe kernel.function("netif_receive_skb") 
{ 
    printf("--------------------------------------------------------\n"); 
    print_backtrace(); 
    printf("--------------------------------------------------------\n"); 
} 
$ stap netif_receive_skb.stp
--------------------------------------------------------
 0xffffffff8164dc00 : netif_receive_skb+0x0/0x90 [kernel]
 0xffffffff8164e280 : napi_gro_receive+0xb0/0x130 [kernel]
 0xffffffff81554537 : handle_incoming_queue+0xe7/0x100 [kernel]
 0xffffffff815555d9 : xennet_poll+0x279/0x430 [kernel]
 0xffffffff8164ee09 : net_rx_action+0x139/0x250 [kernel]
 0xffffffff810702cd : __do_softirq+0xdd/0x300 [kernel]
 0xffffffff8107088e : irq_exit+0x11e/0x140 [kernel]
 0xffffffff8144e785 : xen_evtchn_do_upcall+0x35/0x50 [kernel]
 0xffffffff8176c9ed : xen_hvm_callback_vector+0x6d/0x80 [kernel]
```

##### （4）获取函数参数

由于编译器优化，有些函数参数用`-L`看不到，也不能用$方式获取。可用SystemTap提供的`*_arg`函数接口，*是根据类型指定的，比如pointer_arg是获取指针类型参数，int_arg是获取整型参数，类似的还有long_arg、longlong_arg、uint_arg、ulong_arg、ulonglong_arg、s32_arg、s64_arg、u32_arg、u64_arg：

```bash
$ stap -L 'kernel.function("sys_open")' 
kernel.function("SyS_open@/build/buildd/linux-lts-trusty-3.13.0/fs/open.c:1011") $ret:long int
$ cat sys_open.stp 
probe kernel.function("sys_open").call
{
    printf("filename: %p(%s), flags: %d, mode: %x\n", pointer_arg(1), kernel_string(pointer_arg(1)), int_arg(2), int_arg(3));
}
$ stap sys_open.stp 
filename: 0xc2081d2120(/proc/stat), flags: 524288, mode: 0
filename: 0x7facec00e838(/root/opt/libexec/systemtap/stapio), flags: 0, mode: 1b6
```

##### （5）获取全局变量

有时候用$可以直接获取到全局变量，但有时候又获取不到，那可以试试@var： 比如获取nginx的全局变量ngx_cycyle：

```bash
$ cat get_ngx_cycle.stp
probe process("/home/admin/tengine/bin/nginx").function("ngx_process_events_and_timers").call {
    printf("ngx_cycle->connections: %d\n", $ngx_cycle->connections)
    exit()
}

$ stap get_ngx_cycle.stp
semantic error: while processing probe process("/home/admin/tengine/bin/nginx").function("ngx_process_events_and_timers@src/event/ngx_event.c:225").call from: process("/home/admin/tengine/bin/nginx").function("ngx_process_events_and_timers").call

semantic error: unable to find local 'ngx_cycle', [man error::dwarf] dieoffset 0x73ca8 in /home/admin/tengine/bin/nginx, near pc 0x434152 in ngx_process_events_and_timers src/event/ngx_event.c (alternatives: $cycle, $delta, $timer, $flags)): identifier '$ngx_cycle' at get_ngx_cycle.stp:3:44
        source:     printf("ngx_cycle->connections: %d\n", $ngx_cycle->connections)
                                                           ^

Pass 2: analysis failed.  [man error::pass2]

$ cat get_ngx_cycle.stp
probe process("/home/admin/tengine/bin/nginx").function("ngx_process_events_and_timers").call {
    ngx_cycle = @var("ngx_cycle@src/core/ngx_cycle.c")  # 获取全局变量
    printf("ngx_cycle->connections: %d\n", ngx_cycle->connections)
    exit()
}

$ stap get_ngx_cycle.stp
ngx_cycle->connections: 19507312
```

##### （6）获取数据结构成员

```c
typedef struct {
    size_t      len;
    u_char     *data;
} ngx_str_t;

struct ngx_http_request_s {
    ......
    ngx_uint_t                        method;
    ngx_uint_t                        http_version;

    ngx_str_t                         request_line;
    ngx_str_t                         raw_uri;
    ngx_str_t                         uri;
    ......
};
```

上面这个是nginx里面的http请求结构里面的几个成员，在C语言里，如果r是struct ngx_http_request_t *，那么要获取uri的data是这样的：r->uri.data，但在SystemTap里面，不管是指针还是数据结构，都是用->访问其成员：

```bash
$ cat get_http_uri.stp
probe process("/home/admin/tengine/bin/nginx").function("ngx_http_process_request").call {
    printf("r->uri.len: %d, r->uri.data: %p\n", $r->uri->len, $r->uri->data)
}

$ stap get_http_uri.stp
r->uri.len: 1, r->uri.data: 0x1276f94
r->uri.len: 1, r->uri.data: 0x11d5fc4
r->uri.len: 1, r->uri.data: 0x124fd24
```

##### （7）输出整个数据结构

SystemTap有两个语法可以输出整个数据结构：在变量的后面加1个或者2个$即可（1个表示不展开子结构，2个表示展开子结构）：

```bash
$ cat get_r_pool.stp
probe process("/home/admin/tengine/bin/nginx").function("ngx_http_process_request").call {
    printf("$r->pool$: %s\n$r->pool$$: %s\n", $r->pool$, $r->pool$$)
}
$ stap get_r_pool.stp
$r->pool$: {.d={...}, .max=4016, .current=0x161acd0, .chain=0x0, .large=0x0, .cleanup=0x0, .log=0x161c690}
$r->pool$$: {.d={.last="a", .end="", .next=0x1617650, .failed=0}, .max=4016, .current=0x161acd0, .chain=0x0, .large=0x0, .cleanup=0x0, .log=0x161c690}
```

其中r->pool的结构如下：

```c
typedef struct {
    u_char               *last;
    u_char               *end;
    ngx_pool_t           *next;
    ngx_uint_t            failed;
} ngx_pool_data_t;

struct ngx_pool_s {
    ngx_pool_data_t       d;
    size_t                max;
    ngx_pool_t           *current;
    ngx_chain_t          *chain;
    ngx_pool_large_t     *large;
    ngx_pool_cleanup_t   *cleanup;
    ngx_log_t            *log;
#if  (NGX_DEBUG_POOL)
    size_t                size;
    ngx_pool_stat_t      *stat;
#endif
};
```

##### （8）输出字符串指针

用户态使用：user_string、user_string_n 内核态使用：kernel_string、kernel_string_n、user_string_quoted

```bash
$ cat get_http_uri.stp
probe process("/home/admin/tengine/bin/nginx").function("ngx_http_process_request").call {
    printf("r->uri: %s\nr->uri(n): %s\n", user_string($r->uri->data), user_string_n($r->uri->data, $r->uri->len))
}

$ stap get_http_uri.stp
r->uri: /?id=1 HTTP/1.1
User-Agent
r->uri(n): /
```

user_string_quoted是获取用户态传给内核的字符串，代码中一般有__user宏标记：

```bash
$ cat sys_open.stp
probe kernel.function("sys_open")
{
    printf("filename: %s\n", user_string_quoted(pointer_arg(1)));
}
$ stap sys_open.stp 
filename: "/var/log/auth.log"
filename: "/proc/stat"
filename: "/proc/uptime"
```

##### （9）指针类型转换

SystemTap提供@cast来实现指针类型转换，比如可以将void *转成自己需要的类型：

```bash
$ cat get_c_fd.stp 
probe process("/home/admin/tengine/bin/nginx").function("ngx_http_process_request_line").call {
    printf("c->fd: %d\n", @cast($rev->data, "ngx_connection_t")->fd)
}

$ stap get_c_fd.stp 
c->fd: 3
c->fd: 28
c->fd: 30
c->fd: 32
c->fd: 34
^C
```

##### （10）定义某个类型的变量

其实就是把转换后的变量地址保存下来。

同样是用[@cast](https://my.oschina.net/cast)，定义一个变量用来保存其转换后的地址即可，用法如下：

```bash
$ cat get_c.stp 
probe process("/home/admin/tengine/bin/nginx").function("ngx_http_process_request_line").call {
    c = &@cast($rev->data, "ngx_connection_t")
    printf("c->fd: %d, c->requests: %d\n", c->fd, c->requests)
}

$ stap get_c.stp 
c->fd: 3, c->requests: 1
c->fd: 28, c->requests: 1
c->fd: 30, c->requests: 1
^C
```

##### （11）多级指针用法

通过[0]去解引用，类似数组。

```bash
$ cat cc_multi_pointer.c
#include <stdio.h>

struct test {
    int count;
};

int main(int argc, char *argv[])
{   
    struct test t = {.count = 5566};
    struct test *pt = &t;
    struct test **ppt = &pt;

    printf("t.count: %d, pt->count: %d, ppt->count: %d\n", t.count, pt->count, (*ppt)->count);

    return 0;
}

$ gcc -Wall -g -o cc_multi_pointer ./cc_multi_pointer.c

$ cat cc_multi_pointer.stp
probe process("./cc_multi_pointer").statement("main@./cc_multi_pointer.c:13")
{   
    printf("$t->count: %d, $pt->count: %d, $ppt->count: %d", $t->count, $pt->count, $ppt[0]->count);
}

$ ./cc_multi_pointer
t.count: 5566, pt->count: 5566, ppt->count: 5566

$ stap ./cc_multi_pointer.stp -c './cc_multi_pointer'
t.count: 5566, pt->count: 5566, ppt->count: 5566
$t->count: 5566, $pt->count: 5566, $ppt->count: 5566
```

##### （12）遍历C语言数组

下面是在nginx处理请求关闭时遍历请求头的例子：

```bash
$ cat debug_http_header.stp
probe process("/home/admin/tengine/bin/nginx").function("ngx_http_finalize_request").call {
    i = 0
    headers_in_part = &$r->headers_in->headers->part
    headers = &@cast(headers_in_part->elts, "ngx_table_elt_t")[0]
    while (headers) {
        if (i >= headers_in_part->nelts) {
            if (!headers_in_part->next) {
                break
            }
            headers_in_part = headers_in_part->next;
            headers = &@cast(headers_in_part->elts, "ngx_table_elt_t")[0] # 链表中下一个元素
            i = 0
        }
        h = &@cast(headers, "ngx_table_elt_t")[i]    # 结构中包含数组
        printf("%s: %s\n", user_string_n(h->key->data, h->key->len), user_string_n(h->value->data, h->value->len))
        i += 1
    }
}

$ stap debug_http_header.stp
User-Agent: curl/7.29.0
Host: 127.0.0.1:20090
Accept: */*
```

##### （13）查看函数指针所指的函数名

获取一个地址所对应的符号： 用户态：usymname 内核态：symname

```bash
$ cat get_c_handler.stp
probe process("/home/admin/tengine/bin/nginx").function("ngx_http_process_request_line").call {
    c = &@cast($rev->data, "ngx_connection_t")
    printf("c->read->handlers: %s, c->write->handler: %s\n", usymname(c->read->handler), usymname(c->write->handler))
}

$ stap get_c_handler.stp
c->read->handlers: ngx_http_process_request_line, c->write->handler: ngx_http_empty_handler
^C
```

##### （14）修改进程中的变量

```bash
$ cat stap_set_var.c -n     
     1  #include <stdio.h>
     2
     3  typedef struct policy {
     4      int     id;
     5  } policy_t;
     6
     7  int main(int argc, char *argv[])
     8  {
     9      policy_t policy;
    10      policy_t *p = &policy;
    11      policy_t **pp;
    12
    13      p->id = 111;
    14
    15      printf("before stap set, p->id: %d\n", p->id);
    16
    17      pp = &p;
    18
    19      printf("after stap set, p->id: %d, (*pp)->id: %d\n", p->id, (*pp)->id);
    20
    21      return 0;
    22  }

$ gcc -Wall -g -o ./stap_set_var ./stap_set_var.c      

$ cat stap_set_var.stp
probe process("./stap_set_var").statement("main@./stap_set_var.c:17")
{
    $p->id = 222;
    printf("$p$: %s\n", $p$)
}

$ stap -g stap_set_var.stp -c ./stap_set_var  # -c 表示执行程序； -g 表示guru模式下才能修改变量
before stap set, p->id: 111
after stap set, p->id: 222, (*pp)->id: 222
$p$: {.id=222}
```

可以看出在第17行用SystemTap修改后的值在第19行就生效了。 需要注意的是stap要加-g参数在guru模式下才能修改变量的值。

##### （15）跟踪进程执行流程

thread_indent(n): 补充空格。

ppfunc(): 当前探测点所在的函数。

在call探测点调用thread_indent(4)补充4个空格，在return探测点调用thread_indent(-4)回退4个空格，效果如下：

```bash
$ cat trace_nginx.stp
probe process("/home/admin/tengine/bin/nginx").function("*@src/http/ngx_http_*").call
{
    printf("%s -> %s\n", thread_indent(4), ppfunc());
}

probe process("/home/admin/tengine/bin/nginx").function("*@src/http/ngx_http_*").return
{
    printf("%s <- %s\n", thread_indent(-4), ppfunc());
}

$ stap trace_nginx.stp
     0 nginx(11368):    -> ngx_http_init_connection
    21 nginx(11368):    <- ngx_http_init_connection
     0 nginx(11368):    -> ngx_http_wait_request_handler
    30 nginx(11368):        -> ngx_http_create_request
    41 nginx(11368):        <- ngx_http_create_request
    55 nginx(11368):        -> ngx_http_process_request_line
    72 nginx(11368):            -> ngx_http_read_request_header
    78 nginx(11368):            <- ngx_http_read_request_header
    91 nginx(11368):            -> ngx_http_parse_request_line
    99 nginx(11368):            <- ngx_http_parse_request_line
   109 nginx(11368):            -> ngx_http_process_request_uri
   115 nginx(11368):            <- ngx_http_process_request_uri
   127 nginx(11368):            -> ngx_http_process_request_headers
   138 nginx(11368):                -> ngx_http_read_request_header
   143 nginx(11368):                <- ngx_http_read_request_header
   155 nginx(11368):                -> ngx_http_parse_header_line
   163 nginx(11368):                <- ngx_http_parse_header_line
   178 nginx(11368):                -> ngx_http_process_user_agent
   185 nginx(11368):                <- ngx_http_process_user_agent
   192 nginx(11368):                -> ngx_http_parse_header_line
   198 nginx(11368):                <- ngx_http_parse_header_line
   208 nginx(11368):                -> ngx_http_process_host
   222 nginx(11368):                    -> ngx_http_validate_host
   229 nginx(11368):                    <- ngx_http_validate_host
   239 nginx(11368):                    -> ngx_http_set_virtual_server
   252 nginx(11368):                        -> ngx_http_find_virtual_server
   259 nginx(11368):                        <- ngx_http_find_virtual_server
   263 nginx(11368):                    <- ngx_http_set_virtual_server
   266 nginx(11368):                <- ngx_http_process_host
   274 nginx(11368):                -> ngx_http_parse_header_line
   279 nginx(11368):                <- ngx_http_parse_header_line
   287 nginx(11368):                -> ngx_http_parse_header_line
   292 nginx(11368):                <- ngx_http_parse_header_line

   .....

  2072 nginx(11368):                                <- ngx_http_finalize_request
  2076 nginx(11368):                            <- ngx_http_core_content_phase
  2079 nginx(11368):                        <- ngx_http_core_run_phases
  2083 nginx(11368):                    <- ngx_http_handler
  2093 nginx(11368):                    -> ngx_http_run_posted_requests
  2100 nginx(11368):                    <- ngx_http_run_posted_requests
  2103 nginx(11368):                <- ngx_http_process_request
  2107 nginx(11368):            <- ngx_http_process_request_headers
  2111 nginx(11368):        <- ngx_http_process_request_line
  2114 nginx(11368):    <- ngx_http_wait_request_handler
     0 nginx(11368):    -> ngx_http_keepalive_handler
    26 nginx(11368):        -> ngx_http_close_connection
    79 nginx(11368):        <- ngx_http_close_connection
    83 nginx(11368):    <- ngx_http_keepalive_handler
```

##### （16）查看代码执行路径

pp(): 输出当前被激活的探测点

```bash
$ cat ngx_http_process_request.stp
probe process("/home/admin/tengine/bin/nginx").statement("ngx_http_process_request@src/http/ngx_http_request.c:*") {
    printf("%s\n", pp())
}

$ stap ngx_http_process_request.stp 
process("/home/admin/tengine/bin/nginx").statement("ngx_http_process_request@src/http/ngx_http_request.c:2762")
process("/home/admin/tengine/bin/nginx").statement("ngx_http_process_request@src/http/ngx_http_request.c:2768")
process("/home/admin/tengine/bin/nginx").statement("ngx_http_process_request@src/http/ngx_http_request.c:2771")
```

可以看出该函数哪些行被执行。

##### （17）正则匹配过滤

在排查问题时，可以利用一些正则匹配来获取自己想要的信息，比如下面是只收集*.j9.com的堆栈：

```bash
$ cat debug_tengine_5xx.stp 
probe process("/home/admin/tengine/bin/t-coresystem-tengine-cdn").function("ngx_http_finalize_request").call {
    rc = $rc
    if (rc < 0) {
        host = "(null)"
        if ($r->headers_in->server->len != 0) {
            host = user_string_n($r->headers_in->server->data, $r->headers_in->server->len)
        } else {
            cscf = &@cast($r->srv_conf, "ngx_http_core_srv_conf_t")[@var("ngx_http_core_module@src/http/ngx_http_core_module.c")->ctx_index]
            if (cscf->server_name->len != 0) {
                 host = user_string_n(cscf->server_name->data, cscf->server_name->len)
            }
        }

        if (host =~ ".*\.j9\.com") {
            printf("rc: %d, host: %s\n", rc, host)
            print_ubacktrace()
        }
    }
}

$ stap debug_tengine_5xx.stp
WARNING: Missing unwind data for module, rerun with 'stap -d /lib64/libc-2.12.so'
rc: -4, host: www.j9.com
 0x49af2e : ngx_http_finalize_request+0xe/0x480 [/home/admin/tengine/bin/t-coresystem-tengine-cdn]
 0x492eab : ngx_http_core_content_phase+0x2b/0x130 [/home/admin/tengine/bin/t-coresystem-tengine-cdn]
 0x48e74d : ngx_http_core_run_phases+0x3d/0x50 [/home/admin/tengine/bin/t-coresystem-tengine-cdn]
 0x514c3c : ngx_http_lua_socket_tcp_read+0x44c/0x590 [/home/admin/tengine/bin/t-coresystem-tengine-cdn]
 0x513150 : ngx_http_lua_socket_tcp_handler+0x30/0x50 [/home/admin/tengine/bin/t-coresystem-tengine-cdn]
 0x475b96 : ngx_event_process_posted+0x36/0x40 [/home/admin/tengine/bin/t-coresystem-tengine-cdn]
 0x47d4d8 : ngx_worker_process_cycle+0x138/0x260 [/home/admin/tengine/bin/t-coresystem-tengine-cdn]
 0x47a38a : ngx_spawn_process+0x1ca/0x5e0 [/home/admin/tengine/bin/t-coresystem-tengine-cdn]
 0x47c73c : ngx_start_worker_processes+0x7c/0x100 [/home/admin/tengine/bin/t-coresystem-tengine-cdn]
 0x47db5f : ngx_master_process_cycle+0x3af/0x9b0 [/home/admin/tengine/bin/t-coresystem-tengine-cdn]
 0x45a740 : main+0xa90/0xb50 [/home/admin/tengine/bin/t-coresystem-tengine-cdn]
 0x3623e1ecdd [/lib64/libc-2.12.so+0x1ecdd/0x38d000]
```

##### （18）关联数组用法

就是数组的定义和使用。

SystemTap的关联数组必须是全局变量，需要用global进行声明，其索引可以支持多达9项索引域,各域间以逗号隔开。支持 =, ++ 与 +=操作,其默认的初始值为0。 例如：

```bash
$ cat stap_array.stp 
global reads
probe vfs.read {
    reads[execname(), pid()] ++
}
probe timer.s(3) {
    foreach ([execname, pid] in reads) {
        printf("%s(%d) : %d \n", execname, pid, reads[execname, pid])
    }
    print("============================\n")
    delete reads
}

$ stap stap_array.stp 
stapio(18716) : 16 
rsyslogd(770) : 1 
docker(743) : 3 
IFSWatch(5594) : 30 
QThread(5594) : 6 
AliYunDunUpdate(1057) : 4 
sshd(15118) : 1 
sshd(15191) : 1 
============================
stapio(18716) : 16 
sshd(15191) : 3 
docker(743) : 3 
IFSWatch(5594) : 30 
sshd(15118) : 2 
QThread(5594) : 12 
AliYunDunUpdate(1057) : 8 
============================
^C
```

也可以用+、-进行排序：

```bash
$ cat stap_array.stp
global reads
probe vfs.read {
    reads[execname(), pid()] ++
}
probe timer.s(3) {
    foreach ([execname, pid+] in reads) {
        printf("%s(%d) : %d \n", execname, pid, reads[execname, pid])
    }
    print("============================\n")
    delete reads
}

$ stap stap_array.stp 
docker(743) : 3 
rsyslogd(770) : 1 
AliYunDunUpdate(1057) : 12 
IFSWatch(5594) : 30 
QThread(5594) : 12 
sshd(15118) : 2 
sshd(15191) : 2 
stapio(19021) : 16 
============================
docker(743) : 3 
AliYunDunUpdate(1057) : 12 
IFSWatch(5594) : 30 
QThread(5594) : 6 
sshd(15118) : 1 
sshd(15191) : 19 
stapio(19021) : 16 
============================
^C
```

##### （19）调试内存泄露及double-free

堆块申请时，将堆块地址的引用数+1，释放时再-1，如果释放后引用数<0，说明释放了两次。

```c
probe begin {
    printf("=============begin============\n")
}

//记录内存分配和释放的计数关联数组
global g_mem_ref_tbl
//记录内存分配和释放的调用堆栈关联数组
global g_mem_bt_tbl

// 在堆分配函数处设检测点，保存新申请的堆块地址（引用数+1），并记录栈回溯
probe process("/lib/x86_64-linux-gnu/libc.so.6").function("__libc_malloc").return, process("/lib/x86_64-linux-gnu/libc.so.6").function("__libc_calloc").return {
    if (target() == pid()) {
        if (g_mem_ref_tbl[$return] == 0) {
            g_mem_ref_tbl[$return]++
            g_mem_bt_tbl[$return] = sprint_ubacktrace()
        }
    }
}

// 如果释放后引用小于0，说明产生了double-free
probe process("/lib/x86_64-linux-gnu/libc.so.6").function("__libc_free").call {
    if (target() == pid()) {
        g_mem_ref_tbl[$mem]--

        if (g_mem_ref_tbl[$mem] == 0) {
            if ($mem != 0) {
                //记录上次释放的调用堆栈
                g_mem_bt_tbl[$mem] = sprint_ubacktrace()
            }
        } else if (g_mem_ref_tbl[$mem] < 0 && $mem != 0) {
            //如果调用free已经失衡，那就出现了重复释放内存的问题，这里输出当前调用堆栈，以及这个地址上次释放的调用堆栈
            printf("MMMMMMMMMMMMMMMMMMMMMMMMMMMM\n")
            printf("g_mem_ref_tbl[%p]: %d\n", $mem, g_mem_ref_tbl[$mem])
            print_ubacktrace()
            printf("last free backtrace:\n%s\n", g_mem_bt_tbl[$mem])
            printf("WWWWWWWWWWWWWWWWWWWWWWWWWWWW\n")
        }
    }
}

probe end {
    //最后输出产生泄漏的内存是在哪里分配的
    printf("=============end============\n")
    foreach(mem in g_mem_ref_tbl) {
        if (g_mem_ref_tbl[mem] > 0) {
            printf("%s\n", g_mem_bt_tbl[mem])
        }
    }
}
```

详细请看：http://blog.csdn.net/wangzuxi/article/details/44901285

##### （20）嵌入C代码

在进程fork出子进程时打印出进程id和进程名:

```bash
$ cat copy_process.stp
function getprocname:string(task:long)
%{
    struct task_struct *task = (struct task_struct *)STAP_ARG_task; # 获取task变量
    snprintf(STAP_RETVALUE, MAXSTRINGLEN, "pid: %d, comm: %s", task->pid, task->comm);
%}

function getprocid:long(task:long)
%{
    struct task_struct *task = (struct task_struct *)STAP_ARG_task;
    STAP_RETURN(task->pid);
%}

probe kernel.function("copy_process").return
{
    printf("copy_process return: %p, pid: %d, getprocname: %s, getprocid: %d\n", $return, $return->pid, getprocname($return), getprocid($return));
}
$ stap -g copy_process.stp
copy_process return: 0xffff880039f61800, pid: 12212, getprocname: pid: 12212, comm: bash, getprocid: 12212
copy_process return: 0xffff880039f61800, pid: 12212, getprocname: pid: 12212, comm: bash, getprocid: 12212
copy_process return: 0xffff880039f63000, pid: 12213, getprocname: pid: 12213, comm: cc_epoll, getprocid: 12213
copy_process return: 0xffff880039f63000, pid: 12213, getprocname: pid: 12213, comm: cc_epoll, getprocid: 12213
```

**注意**： 1）、SystemTap脚本里面嵌入C语言代码要在每个大括号前加%前缀，是%{…… %} 而不是%{ …… }%； 2）、获取脚本函数参数要用STAP_ARG_前缀； 3）、一般long等返回值用STAP_RETURN，而string类型返回值要用snprintf、strncat等方式把字符串复制到STAP_RETVALUE里面。

##### （21）调试内核模块

详情请参考[使用SystemTap调试新增内核模块](http://blog.chinaunix.net/uid-14528823-id-4726046.html)。

注意：

1.使用SystemTap调试内核模块，探测点的编写格式示例为： module("ext3").function("ext3_*")；

2.需要将自己的模块cp到/lib/modules/uname -r/extra目录中，否则找不到符号，如果/lib/modules/uname -r/目录下没有extra这个目录，自己mkdir一下就可以。

```c
// 命令：$ stap hello.stp > hello_output.txt &
//      $ rmmod hello
probe module("hello").function("test")
{
        print("Hello Systemtap!\n")
}
// 假设编写hello.c，模块名为hello，其中包含函数test
```

##### （22）错误提示及解决办法

错误提示1：

```bash
ERROR: MAXACTION exceeded near keyword at debug_connection.stp:86:9
ERROR: MAXACTION exceeded near operator '->' at debug_connection.stp:84:30
```

解决办法： 加上stap参数：-DMAXACTION=102400，如果还报这种类型的错误，只需把102400调成更大的值即可。

错误提示2：

```bash
WARNING: Number of errors: 0, skipped probes: 82
```

解决办法： 加上-DMAXSKIPPED=102400和-DSTP_NO_OVERLOAD参数

还有一些可以去掉限制的宏：

MAXSTRINGLEN：这个宏会影响sprintf的buffer大小，默认为512字节。 MAXTRYLOCK：对全局变量进行try lock操作的次数，超过则次数还拿不到锁则放弃和跳过该探测点，默认值为1000.全局变量多的时候可以把这个宏开大一点。

### 参考：

[SystemTap使用技巧](https://my.oschina.net/sherrywangzh/blog/1518223)