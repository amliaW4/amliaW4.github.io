
title: IDA 常用工具安装 (更新中)

date: 2018-03-21 14:39:16

categories:
- tools
- IDA


Mac 下常用 IDA pro 7.0 插件的安装配置。



# findcrypt3 找加密方式的插件

1. 下载findcrypt.py复制到插件目录

https://github.com/polymorf/findcrypt-yara

IDA 7.0\plugins\findcrypt3.rules

IDA 7.0\plugins\findcrypt3.py

1. 安装：yara-python 



**请一定要用python2 的 pip2 来 安装 yara-python 。**

**请一定要用python2 的 pip2 来 安装 yara-python 。**

**请一定要用python2 的 pip2 来 安装 yara-python 。**



yara-python https://github.com/VirusTotal/yara-python

`pip install yara-python`



参考：https://www.cnblogs.com/zhaijiahui/p/7978897.html



# keypatch 可以直接修改二进制代码的插件

keypatch ： https://github.com/keystone-engine/keypatch

> 支持的CPU架构: 
>
> support Arm, Arm64 (AArch64/Armv8), Hexagon, Mips, PowerPC, Sparc, SystemZ & X86 (include 16/32/64bit).
>
> 支持的平台: 
>
> work everywhere that IDA works, which is on Windows, MacOS, Linux.
>
> Based on Python, so it is easy to install as no compilation is needed.

keypatch底层依赖keystone-engine

> 安装keystone-engine
>
> Windows上32位ida(ida 6.8, 6.9, 6.95, 7.0_x86), 安装keystone-engine, **注意** 检查配套的python32
>
> 关键步骤 
>
> https://github.com/keystone-engine/keystone/releases/download/0.9.1/keystone-0.9.1-python-win32.msi
>
> Windows上64位ida(>=7.0), 安装keystone-engine, **注意** 检查配套的python64
>
> 关键步骤 
>
> https://github.com/keystone-engine/keystone/releases/download/0.9.1/keystone-0.9.1-python-win64.msi

必须要有cmake, 用来编译libkeystone.dylib (libkeystone.dylib, macOS python是universal binary

典型问题: https://github.com/keystone-engine/keypatch/issues/28 

之前装过了 Homebrew 

- install cmake

```shell
brew install cmake
```

- install keystone-engine

```
sudo pip install keystone-engine
```

- 复制 keystone-engine 到 IDA 中的python文件里

我的 python3 是用 brew 安装的，site-packages目录在：

```
/usr/local/lib/python3.6/site-packages
```

然后 复制：

```
sudo cp -r /usr/local/lib/python3.6/site-packages/keystone 
					/Applications/IDA\ Pro\ 7.0/ida.app/Contents/MacOS/python 
```

**如果你的IDAPython搜索路径能够搜索到库文件就不需要复制。**

重启IDA ，不出意外应该可以了。



参考： http://blog.csdn.net/fjh658/article/details/52268907