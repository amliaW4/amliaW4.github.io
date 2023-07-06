---
title: Mac下双VM搭建Windows内核调试环境
comments: true
date: 2018-09-16 21:11:47
categories:
tags:
	- kernel
---



## 0x00 环境

虚拟机软件：VMware Fusion

调试机：Windows 7

被调试机：Windows XP、Windows 7



## 0x01 配置两个虚拟机的串行端口

首先需要给`调试机`和`被调试机`配置一个串行端口用来通讯，找到虚拟机的vmx文件，右键使用文本编辑工具打开.VMX文件，然后追加下面的几行配置串行端口。

**调试机 Win 7：**

```c
serial0.present = "TRUE"
serial0.fileType = "pipe"
serial0.startConnected = "TRUE"
serial0.fileName = "/Users/jibin/Downloads/serial"
serial0.tryNoRxLoss = "FALSE"
serial0.pipe.endPoint = "client"
```

**被调试机 XP：**

```c
serial0.present = "TRUE"
serial0.fileType = "pipe"
serial0.fileName = "/Users/jibin/Downloads/serial"
serial0.tryNoRxLoss = "FALSE"
serial0.pipe.endPoint = "server"
```



可以看到调试机COM端口为 COM2

![img-1](windows-kernel-debug-settings/img-1.png)

右键属性->端口设置，波特率改成115200 ， **两台虚拟机都需要修改，xp 需要修改 boot.ini 文件**



## 0x02 配置虚拟机环境

**被调试机 XP：**

系统盘下找到Boot.ini，去掉这个文件的只读属性，用记事本打开Boot.ini 

```c
[boot loader]
timeout=30
default=multi(0)disk(0)rdisk(0)partition(1)\WINDOWS
[operating systems]
multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="XP Professional with Kernel Debugging" /noexecute=optin /fastdetect /debug /debugport=COM2 /baudrate=115200
multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /noexecute=optin /fastdetect
```

其中最后一行为自己新加，用于创建一个新的调试系统，

/debug 开启内核调试
/debugport=COM2 告诉系统使用哪个端口来链接调试系统和被调试系统
/baudrate=115200 指定串口的数据传输速率



**被调试机 Win 7：**

待补充



## 0x03 开始调试

在调试机win7中打开 windbg 进行配置
File -> kernel debug…   设置对于的 **Port** 和 **Baud Rate**



## 参考 

https://blog.csdn.net/hgy413/article/details/8466000

https://bbs.pediy.com/thread-222660.htm

https://www.cnblogs.com/amliaw4/p/8475573.html











