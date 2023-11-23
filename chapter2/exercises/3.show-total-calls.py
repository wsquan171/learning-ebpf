#!/usr/bin/python3  
from bcc import BPF
import ctypes as ct
from time import sleep

program = r"""
BPF_ARRAY(counts, u64, 1000);

int hello(void *ctx) {
    u64 uid;

    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    uid = uid % 1000;
    counts.increment(uid);
    return 0;
}
"""

b = BPF(text=program)
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

while True:
    sleep(2)
    s = ""
    for k,v in b["counts"].items():
        if v.value == 0:
            continue
        s += f"ID {k.value}: {v.value}\t"
    print(s)

