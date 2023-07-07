
title: 漏洞战争小记

date: 2018-07-08 10:31:46

categories:
- 《漏洞战争》
- 小记


## 栈溢出漏洞分析

!address edi

lmm模块名 v   (lmm查看模块的详细信息)

ub



### 漏洞分析方法

- **基于字符串的漏洞定位分析方法**
  - 通过溢出点附近的字符串定位溢出
- **基于栈回溯的漏洞分析方法**
  - kp
- **基于污点追踪思路的漏洞分析方法**
  - 找到能够控制溢出的函数参数
- **针对ACtiveX控件的漏洞分析方法**
  - 在ImmDbg ALT+E 找到OLEAUT32，双击进入
  - Ctrl+N 搜索 OLEAUT32.DLL 中 DispCallFunc 函数， 首个CALL ECX， 就是调用的函数。
  - 如果poc中包含多个控件函数，就逐个跟进`call ecx`去判断对应的是哪个控件函数。
- **基于OffVis工具的Office漏洞分析方法**



### 调试

- 有时溢出的数据会破坏堆栈不能通过kp定位溢出函数，可以通过报错地址在IDA中找到函数，然后windbg中断入函数，**分配完栈空间后给ebp+4下写入断点**  `ba w 1 地址`。

- 调试rep movsd溢出函数 ， 可能多次调用溢出函数，导致不动准确的定位溢出函数何时被调用，rep movsd溢出报错后可能会看到ecx的次数，确定ecx， 下条件断点ecx==次数。

- 内存断点断不下就用硬件断点。

- [py-office-tools](https://github.com/ohio813/py-office-tools) 分析格式

  > C:\\> python pyOffice.py -f exploit.xlb > exploit.txt”

- 解决动态加载：

  - 下断点发现断不下来，可能是poc是动态加载，通过日志找到加载模块，用调试器加载然后下断点。

- 解决动态加载：

  - Alt+E 找到MSCOMCTL模块对应的文件路径，然后使用ImmDbg加载运行，然后在目标断点下断。



### 漏洞利用

- 覆盖返回地址
- 覆盖SEH结构

- pdf中嵌套JavaScript代码实现 `Heap Spary` 然后通过ROP跳到 `0x0c0c0c0c`。

  - shellcode内容，绕过DEP(数据执行保护) ， ROP位于不受ASLR保护的区域。

  1. ROP，调用CreateFileA函数
  2. ROP，调用CreateFileMapping函数 ，创建一个可执行的内存镜像。
  3. ROP，调用MapViewOffile函数
  4. ROP，通过类似memcpy函数复制到可执行可读写的内存中(绕过DEP)。目标地地址MapViewOffile返回地址，原地址是shellcode地址



### 杂项

- 分析漏洞位置，查找相关数据结构。
- 稳定的跳转地址，各个版本dll中不变的跳转地址



## 堆溢出漏洞分析

**Windbg命令：**

`!heap -p -a`  、 `dt _HEAP_FREE_ENTRY `  、 `dt _LIST_ENTRY`

![img-1](漏洞战争小记/img-1.png)

软件调试中常用htc、hpc、hfc、`hpa`。

dd poi(ebp+8)

ln 69a69868

### 漏洞分析方法

- **基于HeapPage漏洞分析方法**

- !gflag +hpa 开启页堆进行调试

    - **基于导图推算的漏洞分析方法**	**(CVE-2012-0003需要重新分析)**
    - win+r : cmd  ， `gflags -i ProcessName.exe +hpa`  开启页堆。
    - ImmDbg `Shift+F4`  打开条件记录断点设置 ，查看log `Alt+L `  , 可以观察数值的变化。

- **基于HTC的漏洞分析方法**

    - `gflag.exe -i 目标.exe +htc` 来判断是否发生溢出

      用溢出错误处地址减去首次中断的目标地址。确定允许复制的数据最大长度。

      Heap block at 030609F0 modified at 03060D48 past requested size of 350。

      大小为350堆块 `0x030609F0` 在 `0x03060D48` 处被修改

- **基于HPA的漏洞分析方法**	**(CVE-2012-1876需要重新分析)**



### 调试

- 解决动态加载POC的两种方法P88：

  - 1)利用 OD 或者 ImmDbg 调试器加载目标DLL，按F9运行到溢出函数地址下断。然后附加进程，再打开目标poc。
  - **2)利用WinDbg的 `sxe ld:ModuleName` 命令在首次加载目标模块时断下，然后再对地址下断点。**

- 页堆失效，不弄中断

  - win+r : cmd  ， `gflags -i ProcessName.exe +hpa`  开启页堆。

- WinDbg不支持子进程调试

  - `.childdbg 1`   开启子进程调试，

    通过 `sxe ld:目标模块` 在模块加载时中断，然后对目标地址下断点。



### 漏洞利用

- 通过堆溢出可以覆盖虚函数 P134

- P149



## 整数溢出漏洞分析

![img-2](漏洞战争小记/img-2.png)

![img-3](漏洞战争小记/img-3.png)

unsigned short int size = 2;    // 65540时为4

2 - 5 = 65533

- 查找相关函数信息：
  - recordset site:http://www.geoffchappell.com  来查找recordset函数



### 漏洞分析方法

- 基于堆分配记录的漏洞分析方法
  - `!heap -p -a 溢出堆块地址` 可以查看被溢出堆块的信息， 以及该堆块的分配过程。

AB无符号, GL有符号。即包含A或B的跳转指令为无符号指令，包含G或L的为有符号指令.

![img-4](漏洞战争小记/img-4.png)

- **基于条件记录断点的漏洞分析方**

  - `f2` 然后 `shift+f4`

    https://blog.didierstevens.com/programs/pdf-tools/

- **基于源码调试的漏洞分析方法**

  - windbg设置条件记录断点：`bu 0x55ea6514 “.if(1){.echo ’num ==’;dd ebx l1;gc}”`

- **基于类函数定位的漏洞分析方法**



## 格式化字符串漏洞分析

![img-6](漏洞战争小记/img-6.png)

![img-5](漏洞战争小记/img-5.png)

![img-7](漏洞战争小记/img-7.png)

```asm
mov ptr[EAX], ECX
```

我们可以通过控制打印栈上内容的数量（即增加%x的数量），控制EAX的值（目标地址）。

可以通过控制打印字符的长度（用%100x，%200x等来控制打印长度），控制ECX的值（要写入大小）。

最后利用mov ptr[EAX],ECX来任意地址写。
https://cartermgj.github.io/2016/11/17/windows-fsb



### 漏洞分析方法

- **通过源码对比分析漏洞**
- **通过输出消息的漏洞定位方法**



## 双重漏洞释放漏洞分析



### 分析方法

- **通过栈回溯和堆状态判定漏洞类型**
  - !address 
- **基于ROP指令地址的反向追踪**



### 杂项

- 自动化分析shellcode执行行为工具 - scDbg



## 释放后重用



### 漏洞分析方法

- **动态调试快速定位漏洞源码**

  - kv 命令 https://my.oschina.net/u/1426828/blog/1629947
- **通过HPA快速定位漏洞对象**     **(CVE-2013-1347需要重新分析)**
  -  `!gflag -i iexpoler +hpa`
  - `!heap -p -a ecx`
- **使用peepdf分析PDF恶意样本**    **(CVE-2013–3346)**
  - peepdf.py -i -f 恶意样本.pdf
  - -i 开启控制台交互模式，-f 忽略错误强制解析pdf
  - `Objects with JS code (1): [5]`     表示 对象5是一段javascript 代码
  - `OpenAction (1): [1]`       打开PDF后执行的动作，引用对象为1
    - `保存`object 3` 出来的被加密的代码为jsencode`
    - `js_decode file jsencode $> jsdecode`
    - `js_analyse variable jsdecode $> shellcode`
    - `show shellcode `
  - `sctect -v variable shellcode ` 可以模拟运行shellcode
  - [scdbg](https://github.com/dzzie/VS_LIBEMU) 也可以分析， 使用GUI 点击 Example —> Launch

- cve-2015-0313 未分析



## 数组越界访问漏洞分析

- 通过修改样本代码定位漏洞
- 基于源代码对比与跟踪漏洞分析方法



## 内核漏洞分析

CVE-2013-3660 重新分析

CVE-2014-1767 

