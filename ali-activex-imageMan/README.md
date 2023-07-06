---
title: 阿里旺旺ActiveX控件imageMan.dll栈溢出
date: 2018-04-29 15:47:41
categories:
tags:
	- 《漏洞战争》

---



## 环境

XP sp3

6.50.00c



## 基础知识

ActiveX控件imageMan.dll中AutoPic函数没有对参数长度进行有效的检测导致栈溢出。

###  什么是ActiveX

ActiveX是浏览器插件，它是一些软件组件或对象，可以将其插入到WEB网页或其他应用程序中。

浏览器插件总体可以划分为两大阵营，即IE支持的插件以及非IE支持的插件。虽说Activex是微软的亲儿子，但是，现在win10默认安装的Edge浏览器已经不再支持Activex。

### 组件对象模型（COM）

COM技术，那么就会在注册表中注册CLSID：[图源](https://bbs.ichunqiu.com/thread-30357-1-1.html?from=sec)

![img-1](ali-activex-imageMan/img-1.png)

右键IE-Internet属性-程序-管理加载项，可查看已经安装的ActiveX插件。

 ### classid

每个ActiveX组件中可能包含多个class类，每个class类可能包含了多个接口，每个接口可能包含了多个函数。每个class类有一个自己的classid。在调用ActiveX中的某个函数的时候，会事先通过classid来引入class。

注册表 HKEY_CLASSES_ROOT\CLSID中记录的就是classid。每个 classid下面有个typelib，typelib记录的是所属com组件的id。组件id记录在注册表的HKEY_CLASSES_ROOT\TypeLib目录下。

### 分发函数

ActiveX组件中调用函数的机制叫做分发。com组件在调用某个函数时：

1. 首先使用被调用函数的函数名来调用GetIDsOfNames函数，返回值是函数编号(DISPID,又名调度ID）
2. 再使用该函数编号和函数参数来调用Invoke函数。
3. Invoke函数内部调用OLEAUT32!DispCallFunc(HWND ActiveX_instant, dispatchID id) 获取函数地址。

分发接口其实就是存在两个数组，一个存放dispid与接口方法名称的对值（pair），一个存放的是dispid与接口方法指针（函数指针）的对值。先通过函数名来找函数编号，然后利用函数编号来调用函数。GetIDsOfNames函数和Invoke(OLEAUT32!DispCallFunc)函数中分别使用了函数名称表和函数地址表。



## 漏洞分析

在网页中调用ActiveX组件，在浏览器背后都会先后调用`GetIDsOfNames`函数和Invoke函数。因为Invoke函数内部最终要调用`OLEAUT32!DispCallFunc`函数，因此可以在该函数上下断点。

业界普遍的方法是利用OLEAUT32!DispCallFunc函数来对调试函数进行跟踪分析，然后跟进 call ecx。

1. Immunity Debugger 附加 IE进程， `Alt+E`  搜索 OLEAUT32 双机进入
2. Ctrl+N 找到函数 DispCallFunc 双击进入
3. 首个 CALL ECX 下断点。

![img-2](ali-activex-imageMan/img-2.png)

进入函数分析可以翻下， 函数申请了0x31空间![img-3](ali-activex-imageMan/img-3.png)

调试发现eax返回  0 。

![img-4](ali-activex-imageMan/img-4.png)

接着会将上面查找 "/" 所用字符串地址 [ebp-208] - 字符串中 "/" 位置，

因为返回的EAX为0 ，所以要复制的SIZE非常大。

![img-5](ali-activex-imageMan/img-5.png)

这样我们就会一直覆盖到 SEH 为 0x0D0D0D0D ，

因为复制的SIZE非常大，覆盖到了只读区域，出现异常，执行到0x0d0d0d0d 处的shellcode 。

但是不知道为什么，我这里一直不弹框。













## 参考

https://bbs.ichunqiu.com/thread-30357-1-1.html?from=sec



