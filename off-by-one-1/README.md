---
title: off-by-one 
date: 2018-03-28 11:02:32
categories: 
tags: 
	- CTF
	- off-by-one 
---

## 背景

本篇参考[Ox9A82](https://www.anquanke.com/member/121251) 师傅的文章， 并在此基础上添加了少许我在调试时需要注意的问题，记录而已。

https://www.anquanke.com/post/id/84752



## 达成漏洞利用的条件

**off-by-one并不是全都可以达到利用的目的的。申请的chunk大小必须是 (对齐字节倍数+8字节)（x86）的大小进行分配。如果不满足这个条件那么就无法覆盖到inuse位了。**

**下个chunk的前四个字节(Size of previous chunk ) 只有在空闲时有用。**

**如果被分配的chunk大小是 (对齐大小+8字节)(x86) 那么紧接着后面的4字节就是size。**



## off-by-one的分类

off-by-one总共可以分为两种利用方式

### chunk overlapping

off-by-one overwrite 

off-by-one overwrite freed

off-by-one null byte

### unlink

off-by-one small bin

off-by-one large bin



##  off-by-one overwrite allocated

A是发生有off-by-one的堆块，**其中B和C是allocated状态的块**。而且C是我们的攻击目标块。

我们的目标是能够读写块C，那么就应该去构造出这样的内存布局。**然后通过off-by-one去改写块B的size域（注意要保证PREV_INUSE域的值为1，否则会触发unlink导致crash）**以实现把C块给整个包含进来。通过把B给free掉，然后再allocated一个大于B+C的块就可以返回B的地址，并且可以读写块C了。

具体的操作是：     

1. 构成图示的内存布局
2. off-by-one改写B块的size域(增加大小以包含C，PREV_INUSE位保持1)
3. free掉B块
4. malloc一个B+C大小的块
5. 通过返回的地址即可对C任意读写

注意，必须要把C块整个包含进来，否则free时会触发check，导致抛出错误。因为ptmalloc实现时的验证逻辑是当前块的下一块的inuse必须为1，否则在free时会触发异常，这一点本来是为了防止块被double free而做的限制，却给我们伪造堆块造成了障碍。

![allocated-1](off-by-one-1/allocated-1.png)

```C
int main(void){
    char buf[253]="";
    void *A,*B,*C;
    void *Overlapped;
    A=malloc(252);
    B=malloc(252);
    C=malloc(128);
    memset(buf,'a',252);
    buf[252]='x89';  //把C块包含进来  ， 为什么是0x89，调试发现C的chunk size 为89 
    memcpy(A,buf,253);//A存在off-by-one漏洞
    free(B);
    Overlapped=malloc(500);
}
```


## off-by-one overwrite freed

A是发生有off-by-one的堆块，**其中B是free状态的块,C是allocated块**。而且C是我们的攻击目标块。

我们的目标是能够读写块C，那么就应该去构造出这样的内存布局。**然后通过off-by-one去改写块B的size域（注意要保证PREV_INUSE域的值为1）**以实现把C块给整个包含进来。但是这种情况下的B是free状态的,通过增大B块包含C块，然后再allocated一个B+C尺寸的堆块就可以返回B的地址，并且可以读写块C了。

具体的操作是：

1. 构成图示的内存布局


2. off-by-one改写B块的size域(增加大小以包含C，inuse位保持1)


3. malloc一个B+C大小的块


4. 通过返回的地址即可对C任意读写

![allocated-1](off-by-one-1/allocated-1.png)

```c
int main(void){
    char buf[253]="";
    void *A,*B,*C;
    void *Overlapped;
    A=malloc(252);
    B=malloc(252);
    C=malloc(128);
    free(B);
    memset(buf,'a',252);
    buf[252]='x89';
    memcpy(A,buf,253);//A存在off-by-one漏洞
    Overlapped=malloc(400);
}
```

这个DEMO与上面的类似，**覆盖B块的大小**，同样可以overlapping后面的块C，导致可以对C进行任意读写。



## off-by-one null byte (libc-2.19.so 失败 )

(libc-2.19.so 错误 corrupted size vs. prev_size: 0x08c88108 ***)

这种情况就与上面两种有所不同了，在这种情况下溢出的这个字节是一个'x00'字节。这种off-by-one可能是最为常见的，因为诸如:

```
buf=malloc(124);
if(strlen(str)==124){
   strcpy(buf,str);
}
```

就会产生这种null byte off-by-one，即拷贝一个字符串到一个同样长的缓冲区时，并未考虑到NULL字节。

相比于前两种，这种利用方式就显得更复杂，而且对内存布局的要求也更高了。

首先内存布局需要三个块：

![allocated-1](off-by-one-1/allocated-1.png)

其中A,B,C都是allocated块，A块发生了null byte off-by-one,覆盖了B块的inuse位，使B块伪造为空。然后在分配两个稍小的块b1、b2，根据ptmalloc的实现，这两个较小块（不能是fastbin）会分配在B块中。然后只要释放掉b1，再释放掉C，就会引发从原B块到C的合并。那么只要重新分配原B大小的chunk，就会重新得到b2。在这个例子中，b2是我们要进行读写的目标堆块。最后的堆块布局如下所示：

![allocated-1](off-by-one-1/img-2.png)

布局堆块结构如ABC所示

1. off-by-one覆盖B，目的是覆盖掉B的inuse位
2. free B
3. malloc b1,malloc b2
4. free C
5. free b1
6. malloc B
7. overlapping b2

这种利用方式成功的原因有两点:

通过prev_chunk()宏查找前块时没有对size域进行验证

当B块的size域被伪造后，下一块的pre_size域无法得到更新。



## off-by-one small bin  （未成功）

这种方法是要触发unlink宏，因此需要一个指向堆上的指针来绕过fd和bk链表的check。

需要在A块上构造一个伪堆结构，然后覆盖B的pre_size域和inuse域。这样当我们free B时，就会触发unlink宏导致指向堆上的指针ptr的值被改成&ptr-0xC(x64下为&ptr-0x18)。通过这个特点，我们可以覆写ptr指针，如果条件允许的话，几乎可以造成无限次的write-anything-anywhere。

1. 在A块中构造伪small bin结构，并且修改B块的prev_size域和inuse域。
2. free B块
3. ptr指针被改为&ptr-0xC

![img-3](off-by-one-1/img-3.png)

```c
void *ptr;
int main(void){
    int prev_size,size,fd,bk;
    void *p1,*p2;
    char buf[253]="";
  
    p1=malloc(252);
    p2=malloc(252);
  
    ptr=p1;
    prev_size=0;
    size=249;
    fd=(int)(&ptr)-0xC;
    bk=(int)(&ptr)-0x8;
    
    memset(buf,'c',253);
    memcpy(buf,&prev_size,4);
    memcpy(buf+4,&size,4);
    memcpy(buf+8,&fd,4);
    memcpy(buf+12,&bk,4);

    size=248;
    memcpy(&buf[248],&size,4);
    
    buf[252]='x00';
    
    memcpy(p1,buf,253);
    
    free(p2);
}
```

这个DEMO中使用了一个指向堆上的指针ptr，ptr是全局变量处于bss段上。通过重复写ptr值即可实现write-anything-anywhere。



## off-by-one large bin

large bin通过unlink造成write-anything-anywhere的利用方法最早出现于Google的Project Zero项目的一篇文章中，具体链接是

<https://googleprojectzero.blogspot.fr/2014/08/the-poisoned-nul-byte-2014-edition.html>

在这篇文章中，提出了large bin检验仅仅是通过assert断言的形式来进行的，并不能真正的对漏洞进行有效的防护。但是经过我的测试发现，目前版本的ubuntu和CentOS已经均具备有检测large unlink的能力，如果发现存在指针被篡改的情况，则会抛出“corrupted double-linked list(not small)”的错误，之后翻阅了一下glibc中ptmalloc部分的实现代码却并没有发现有检测这部分的代码，猜测大概是后续版本中加入的。因为这种利用方式的意义已经不是很大，这里就不在详细列出步骤也不提供测试DEMO了。

##  参考

https://www.anquanke.com/post/id/84752

