
title: malloc_consolidate() 函数作用

date: 2018-04-15 08:33:05

categories:
- malloc_consolidate()


## 分析

### 0x00 - 堆未初始化，则初始化

进入 `malloc_consolidate()` ，首先通过 `get_max_fast()` 判断当前堆是否已经初始化。当进程第一次调用 `malloc()` 申请分配的时候，`get_max_fast()` 返回值等于 0，此时会进行堆的初始化工作：

```c
  if (get_max_fast () != 0) {
    ...
  }
  else {
    malloc_init_state(av);
    check_malloc_state(av);
  }
```

在 `malloc_init_state()` 里会进行堆的初始化工作，并且会调用 `set_max_fast()` 设置 `global_max_fast` 为 `DEFAULT_MXFAST` ，`DEFAULT_MXFAST` 在 32 位系统上为 64，在 64 位系统上为 128。因而在以后进入 `malloc_consolidate()` 的时候 `get_max_fast()` 返回值都不会等于 0，保证不会重复进行堆的初始化工作。

### 0x01 - 堆已初始化，则清空 fastbin

如果 `get_max_fast()` 返回值不等于 0，说明堆已经初始化，接下来就将 fastbin 中的每一个 chunk 合并整理到 unsorted_bin 或 top_chunk。

因为 `malloc_consolidate()` 会清空 fastbin，因此首先调用 `clear_fastchunks()` 清除 fastbin 标志位：

```c
  if (get_max_fast () != 0) {
    clear_fastchunks(av);

    ...
  }
```

接下来是一个二层循环，第一层遍历 fastbinY 数组，得到每一个固定尺寸的 fastbin 单链表。二层则遍历 fastbin 单链表得到每一个相同尺寸的空闲 chunk。

```c
    /*
      Remove each chunk from fast bin and consolidate it, placing it
      then in unsorted bin. Among other reasons for doing this,
      placing in unsorted bin avoids needing to calculate actual bins
      until malloc is sure that chunks aren't immediately going to be
      reused anyway.
    */

    maxfb = &fastbin (av, NFASTBINS - 1);
    fb = &fastbin (av, 0);
    do {
      p = atomic_exchange_acq (fb, NULL);
      if (p != 0) {
    do {
      check_inuse_chunk(av, p);
      nextp = p->fd;

    ...

    } while ( (p = nextp) != 0);

      }
    } while (fb++ != maxfb);
```

对每一个 chunk，首先尝试向后合并。合并操作即更新 p 的 size 以及指向，然后调用 `unlink()` 宏将后方 chunk 从其链接的 bin 中脱链:

```c
      if (!prev_inuse(p)) {
        prevsize = p->prev_size;
        size += prevsize;
        p = chunk_at_offset(p, -((long) prevsize));
        unlink(av, p, bck, fwd);
      }
```

然后尝试向前合并。向前合并情况复杂点，它的处理是这样的：

1. **如果向前相邻 top_chunk，则直接合并到 top_chunk 后完事，不再理会 unsorted_bin**
2. **如果向前不相邻 top_chunk，则尝试向前合并后插入到 unsorted_bin**

代码如下：

```c
if (nextchunk != av->top) {
        nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

        if (!nextinuse) {
          size += nextsize;
          unlink(av, nextchunk, bck, fwd);
        } else
          clear_inuse_bit_at_offset(nextchunk, 0);

        first_unsorted = unsorted_bin->fd;
        unsorted_bin->fd = p;
        first_unsorted->bk = p;

        if (!in_smallbin_range (size)) {
          p->fd_nextsize = NULL;
          p->bk_nextsize = NULL;
        }

        set_head(p, size | PREV_INUSE);
        p->bk = unsorted_bin;
        p->fd = first_unsorted;
        set_foot(p, size);
      }

      else {
        size += nextsize;
        set_head(p, size | PREV_INUSE);
        av->top = p;
      }
```

## 总结

1. **若 get_max_fast() 返回 0，则进行堆的初始化工作，然后进入第 7 步**
2. **从 fastbin 中获取一个空闲 chunk**
3. **尝试向后合并**
4. **若向前相邻 top_chunk，则直接合并到 top_chunk，然后进入第 6 步**
5. **否则尝试向前合并后，插入到 unsorted_bin 中**
6. **获取下一个空闲 chunk，回到第 2 步，直到所有 fastbin 清空后进入第 7 步**
7. **退出函数**



## 参考

[Glibc：浅谈 malloc_consolidate() 函数具体实现](https://blog.csdn.net/plus_re/article/details/79265805)

