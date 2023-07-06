---
title: ssp leak
comments: true
date: 2018-08-22 10:20:02
categories:
tags:
	- CTF
	- ssp leak
	
---

## 什么是ssp leak （ Stack Smashes Protect leak）

栈溢出如果覆盖了canary ， 就会执行___stack_chk_fail() 函数。

__stack_chk_fail :

```c
void 
__attribute__ ((noreturn)) 
__stack_chk_fail (void) {   
	__fortify_fail ("stack smashing detected"); 
}
```

__fortify_fail : 

```c
void 
__attribute__ ((noreturn)) 
__fortify_fail (msg)
   const char *msg; {
      /* The loop is added only to keep gcc happy. */
      while (1)
         __libc_message (2, "*** %s ***: %s terminated\n", msg, __libc_argv[0] ?: "<unknown>") 
} 
libc_hidden_def (__fortify_fail)
```

__libc_message 会输出 argv[0] 是指向第一个启动参数字符串的指针。

![canary](ssp-leak/canary.png)

所以，只要我们能够输入足够长的字符串覆盖掉argv[0]，我们就能让canary保护输出我们想要地址上的值。 



## 参考

https://veritas501.space/2017/04/28/%E8%AE%BAcanary%E7%9A%84%E5%87%A0%E7%A7%8D%E7%8E%A9%E6%B3%95/