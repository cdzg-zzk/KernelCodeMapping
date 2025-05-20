#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <string.h>

#define PAGE_SIZE (4*1024)
#define BUF_SIZE (1*PAGE_SIZE)
#define OFFSET (0x0)

#define table_size (1*PAGE_SIZE)
#define INSTRUCTION_OFFSET (0x31)

#define NETLINK_TEST 17
#define PAYLOAD 100

#define JUMP_OFFSET (0xd555f207)

#define FUN_OFFSET (0x80)
typedef struct {
    unsigned long addr;
} user_request_t;

typedef struct {
    int response;
} kernel_response_t;

typedef int(*fun_ptr)(int);

uintptr_t calc_jmp_target(uintptr_t base_addr, uint32_t offset_in_module) {
    uintptr_t instr_addr = base_addr + offset_in_module;
	uint8_t *instr_bytes = (uint8_t *)instr_addr;
	int32_t rel32_offset = (int32_t)(instr_bytes[1] | (instr_bytes[2] << 8) | (instr_bytes[3] << 16) | (instr_bytes[4] << 24));
    uintptr_t target_addr = instr_addr + 5 + rel32_offset; // jmp rel32 的偏移是相对于下一条指令
    return target_addr;
}

void* build_jmp_table(unsigned long addr)
{
	// void *mapped_addr = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS , -1, OFFSET);
	void *mapped_addr = mmap((void*)addr, table_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(mapped_addr == MAP_FAILED) {
		perror("mmap failed");
		exit(-1);
	}
	printf("adddr: %lx    mapped_addr: %lx\n", addr, (unsigned long)mapped_addr);
	// unsigned char jmp_code[] = {0x48, 0x8d, 0x64, 0x24, 0x08, 0xc3};
	unsigned char jmp_code[] = {0xc3};

	memcpy((void*)addr, jmp_code, sizeof(jmp_code));
	return mapped_addr;
}

int test_fun(int a)
{
    int index = 0;
    int ret = 0;
    while(index < a) {
        ret += index;
        index++;
    }
    return ret;
}

static int var1 = 3;
int var2 = 2;
int test_fun3(int a)
{
    int ret = var1 + var2 + a;
    return ret;
}
int main(int argc, const char *argv[])
{
	char *addr = NULL;

	addr = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS , -1, OFFSET);    // 这里不能是SHARED
	if (!addr) {
		perror("mmap failed\n");
		exit(-1);
	}
	printf("ADDR: %lx\n", (unsigned long)addr);
    printf("pid: %d\n", getpid());
	*(char*)addr = 'z';
	// netlink
	struct sockaddr_nl src_addr, dest_addr;
	int skfd, ret, rxlen = sizeof(struct sockaddr_nl);
	struct nlmsghdr *nlh;
	user_request_t request;
	kernel_response_t response;

	skfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_TEST);
	if(skfd < 0) {
		printf("cannot create a netlink sockfd\n");
		return -1;
	}
	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
	src_addr.nl_groups = 0;
	if(bind(skfd, (struct sockaddr*)&src_addr, sizeof(src_addr)) != 0) {
		printf("bind error\n");
		return -1;
	}
	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0;
	dest_addr.nl_groups = 0;

	// 分配 Netlink 消息
	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(user_request_t)));
	memset(nlh, 0, NLMSG_SPACE(sizeof(user_request_t)));
	nlh->nlmsg_len = NLMSG_SPACE(sizeof(user_request_t));
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_type = 0;
	nlh->nlmsg_seq = 0;
	nlh->nlmsg_pid = src_addr.nl_pid;

	// 设置参数
	request.addr = (unsigned long)addr;		// 传入的参数1

	memcpy(NLMSG_DATA(nlh), &request, sizeof(user_request_t));

	// 发送数据到内核
	ret = sendto(skfd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
	if (ret < 0) {
		perror("Sendto Error:");
		exit(-1);
	}

	// 接收来自内核的返回值
	// ************ 为什么收不到正确的值?
	// ************ 是因为用户态 recvfrom() 读取了错误的 NLMSG_DATA
	// ************ 在 user 里，recvfrom() 直接读取 response，但 Netlink 消息的实际数据在 NLMSG_DATA(nlh) 里。
	// ret = recvfrom(skfd, &response, sizeof(kernel_response_t), 0, (struct sockaddr *)&dest_addr, &rxlen);
	ret = recvfrom(skfd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&dest_addr, &rxlen);
	if (ret < 0) {
		perror("Recvfrom Error:");
		exit(-1);
	}
	memcpy(&response, NLMSG_DATA(nlh), sizeof(kernel_response_t));


	// test_fun test
	fun_ptr fun = (fun_ptr)(addr + FUN_OFFSET);
	// build jmp table
	unsigned long jmp_target = calc_jmp_target((uintptr_t)addr, INSTRUCTION_OFFSET);
	printf("jmp_target: %lx\n", jmp_target);
	void* jmp_table_addr = build_jmp_table(jmp_target);
	printf("jmp_table_addr: %lx\n", jmp_table_addr);


	int index = 0;
	unsigned char* array = (unsigned char*)addr; 
	while(index < 18) {
		printf("0x%02x\n", array[index]);
		index++;
	}
	test_fun(10);
	printf("%d\n", fun(10));
	// while(1)
	// 	sleep(5);
	munmap(addr, BUF_SIZE);
	munmap(jmp_table_addr, table_size);
	return 0;
}