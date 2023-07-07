
title: House Of Force

date: 2018-04-16 11:07:54

categories:
- CTF
- House Of Force


## 原理

House Of Force 是一种堆利用方法，但是并不是说 House Of Force 必须得基于堆漏洞来进行利用。如果一个堆(heap based) 漏洞想要通过 House Of Force 方法进行利用，需要以下条件：

1. **能够以溢出等方式控制到 top chunk 的 size 域**
2. **能够自由地控制堆分配尺寸的大小**

House Of Force 产生的原因在于 glibc 对 top chunk 的处理，进行堆分配时，如果所有空闲的块都无法满足需求，那么就会从 top chunk 中分割出相应的大小作为堆块的空间。

当使用 top chunk 分配堆块的 size 值，可以使得 top chunk指向我们期望的任何位置，这就相当于一次任意地址写。然而在 glibc 中，会对用户请求的大小和 top chunk 现有的 size 进行验证。

```c
// 获取当前的top chunk，并计算其对应的大小
victim = av->top;
size   = chunksize(victim);
// 如果在分割之后，其大小仍然满足 chunk 的最小大小，那么就可以直接进行分割。
if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE)) 
{
    remainder_size = size - nb;
    remainder      = chunk_at_offset(victim, nb);
    av->top        = remainder;
    set_head(victim, nb | PREV_INUSE |
            (av != &main_arena ? NON_MAIN_ARENA : 0));
    set_head(remainder, remainder_size | PREV_INUSE);

    check_malloced_chunk(av, victim, nb);
    void *p = chunk2mem(victim);
    alloc_perturb(p, bytes);
    return p;
}
```

然而，如果可以篡改 size 为一个很大值，就可以轻松的通过这个验证，这也就是我们前面说的需要一个能够控制top chunk size 域的漏洞。

一般的做法是把 top chunk 的 size 改为-1，因为在进行比较时会把 size 转换成无符号数，因此 -1 也就是说unsigned long 中最大的数，所以无论如何都可以通过验证。

```c
remainder      = chunk_at_offset(victim, nb);
av->top        = remainder;

/* Treat space at ptr + offset as a chunk */
#define chunk_at_offset(p, s) ((mchunkptr)(((char *) (p)) + (s)))
```

之后这里会把 top 指针更新，接下来的堆块就会分配到这个位置，用户只要控制了这个指针就相当于实现任意地址写任意值(write-anything-anywhere)。

**与此同时，我们需要注意的是，topchunk的size也会更新，其更新的方法如下**

```c
victim = av->top;
size   = chunksize(victim);
remainder_size = size - nb;
set_head(remainder, remainder_size | PREV_INUSE);
```

**所以，如果我们想要下次在指定位置分配大小为 x 的 chunk，**

**我们需要确保 remainder_size 不小于 x+ MINSIZE。**



## 示例

target 值为任意地址到top chunk指针距离。

### 修改got

 `malloc@got.plt` 地址为 `0x601020` ， 那么 target =  0x601020 - 0x10 - top_chunk_addr 

### 修改malloc_hook

malloc_hook 可以在 main_arena 的低地址处可以找到。

target = malloc_hook_addr -  0x10 - top_chunk_addr  

```c
int main()
{
    long *ptr,*ptr2;
    ptr=malloc(0x10);
    ptr=(long *)(((long)ptr)+24);
    *ptr=-1;        // <=== 这里把top chunk的size域改为0xffffffffffffffff
    malloc(target);  // <=== 任意地址到top chunk指针距离
    malloc(0x10);   // <=== 分配块实现任意地址写
}
```



## 例子

HITCON training lab 11



## 总结

HOF的利用要求还是相当苛刻的。

- 首先，需要存在漏洞使得用户能够控制 top chunk 的 size 域。
- 其次，需要用户能自由控制 malloc 的分配大小
- 第三，分配的次数不能受限制

其实这三点中第二点往往是最难办的，CTF 题目中往往会给用户分配堆块的大小限制最小和最大值使得不能通过HOF 的方法进行利用。



## 参考

[House Of Force](https://ctf-wiki.github.io/ctf-wiki/pwn/heap/house_of_force/)

