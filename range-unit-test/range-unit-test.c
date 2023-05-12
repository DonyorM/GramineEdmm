#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <stdbool.h>

#define PAGE_SIZE 4096
#define START_ADDRESS 0x100000000
#define DEFAULT_COUNT 40

int main(int argc, char** argv) {

    for (int j = 0; j < 100000; j++) {
        for (int i = 10; i <= 2000; i += 2){
            void* addr = mmap(NULL, PAGE_SIZE * i * 10
            , PROT_READ | PROT_WRITE, MAP_ANONYMOUS, -1, 0);

            munmap(addr, PAGE_SIZE * i * 5);
        }
    }

    return 0;
}
