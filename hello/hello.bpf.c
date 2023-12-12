// +build ignore
#include "new.bpf.h"

SEC("kprobe/sys_execve")

int hello(void *ctx){
    bpf_printk("Hello")
    return 0;
}