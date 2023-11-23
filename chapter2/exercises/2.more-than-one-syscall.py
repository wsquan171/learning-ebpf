#!/usr/bin/python3  
from bcc import BPF
from time import sleep

program = r"""
BPF_HASH(counter_table);

int hello_open(void *ctx) {
   u64 uid;
   u64 counter = 0;
   u64 *p;

   uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   p = counter_table.lookup(&uid);
   if (p != 0) {
      counter = *p;
   }
   counter += 2;
   counter_table.update(&uid, &counter);
   return 0;
}

int hello_write(void *ctx) {
   u64 uid;
   u64 counter = 0;
   u64 *p;

   uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   p = counter_table.lookup(&uid);
   if (p != 0) {
      counter = *p;
   }
   counter -= 1;
   counter_table.update(&uid, &counter);
   return 0;
}
"""

b = BPF(text=program)
syscall_open = b.get_syscall_fnname("openat")
syscall_write = b.get_syscall_fnname("write")
b.attach_kprobe(event=syscall_open, fn_name="hello_open")
b.attach_kprobe(event=syscall_write, fn_name="hello_write")

# Attach to a tracepoint that gets hit for all syscalls 
# b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

while True:
    sleep(2)
    s = ""
    for k,v in b["counter_table"].items():
        s += f"ID {k.value}: {v.value}\t"
    print(s)
