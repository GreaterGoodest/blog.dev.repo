---
title: "ELF Science Part 2"
date: 2021-12-02T19:30:17-06:00
draft: false
---

## Introduction

This post is part of a three part series (so far) 
- [Part 1](/post/elf_science_p1/)
- [Part 3](/post/elf_science_p3/)

In the last post, we demonstrated a basic method for creating a self-decrypting binary. This is a common technique in many malware variants to add difficulty to the reverse engineering process.

Inspired by some feedback from [@marisa_hacks](https://twitter.com/marisa_hacks), this post will focus on dismantling our previous efforts.

We'll perform dynamic analysis on the binary in order to step through to the point at which it is decrypted. Once we have the binary in it's decrypted form, we will dump out the executable portion of intrest. We will then overwrite the binary with this decrypted data, allowing for better static analysis in future. To take things a step further, we'll then strip out the encryption logic.

## Analysis and Decryption

Let's take a look at the binary resulting from our previous post.

```shell
rgood@debian:~/Playground/self-decrypt$ objdump -D main -M intel| grep "encrypt_me>:" -A 12
0000000000401142 <encrypt_me>:
  401142:       af                      scas   eax,DWORD PTR es:[rdi]
  401143:       b2 73                   mov    dl,0x73
  401145:       1f                      (bad)  
  401146:       b2 77                   mov    dl,0x77
  401148:       c7                      (bad)  
  401149:       4d f4                   rex.WRB hlt 
  40114b:       fa                      cli    
  40114c:       fa                      cli    
  40114d:       12 14 04                adc    dl,BYTE PTR [rsp+rax*1]
  401150:       05 05 6a a7 c3          add    eax,0xc3a76a05

0000000000401155 <main>:
```

As you can see, the encrypt_me function is currently gibberish due to it being encrypted. This function will be decrypted at run time, as the binary has self-decrypting logic built in. 

Let's see that decryption in action:

![GDB Decrypt](/images/gdb-decrypt.gif)

We start by loading the binary into gdb (i'm also using pwndbg). We then begin execution and break at the entrypoint by using the 'start' command. After starting the process, we take a look at the encrypt_me function, and see that it is in it's encrypted state. Next, we set a breakpoint after the decryption is complete (line 32). After reaching that breakpoint, we take another look at the function and see that it is now decrypted.

Our next goal will be to dump out that decrypted data.

## Data Dump

First, let's get back to the point at which encryption is complete, but before the encrypt_me() function is called (line 32).

```bash
In file: /home/rgood/Playground/self-decrypt/main.c
   27         *(int *)addr = *(int *)addr ^ 0xFA;
   28         addr+=1;
   29         function_size -= 1;
   30     }
   31     
 ► 32     encrypt_me();
   33 }
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> disass encrypt_me 
Dump of assembler code for function encrypt_me:
   0x0000000000401142 <+0>:     push   rbp
   0x0000000000401143 <+1>:     mov    rbp,rsp
   0x0000000000401146 <+4>:     lea    rdi,[rip+0xeb7]        # 0x402004
   0x000000000040114d <+11>:    call   0x401040 <puts@plt>
   0x0000000000401152 <+16>:    nop
   0x0000000000401153 <+17>:    pop    rbp
   0x0000000000401154 <+18>:    ret    
End of assembler dump.
```

Here we can see that the encrypt_me() function ranges from address 0x401142 to 0x401154. Let's take a look at the process mappings to see where this address range resides using 'info proc mappings'

```bash
pwndbg> info proc mappings
process 16796
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile                                                
            0x400000           0x401000     0x1000        0x0 /home/rgood/Playground/self-decrypt/main               
            0x401000           0x402000     0x1000     0x1000 /home/rgood/Playground/self-decrypt/main               
            0x402000           0x403000     0x1000     0x2000 /home/rgood/Playground/self-decrypt/main               
            0x403000           0x404000     0x1000     0x2000 /home/rgood/Playground/self-decrypt/main               
            0x404000           0x405000     0x1000     0x3000 /home/rgood/Playground/self-decrypt/main               
            0x405000           0x426000    0x21000        0x0 [heap]                                                 
      0x7ffff7dea000     0x7ffff7e0c000    0x22000        0x0 /usr/lib/x86_64-linux-gnu/libc-2.28.so                 
      0x7ffff7e0c000     0x7ffff7f54000   0x148000    0x22000 /usr/lib/x86_64-linux-gnu/libc-2.28.so                 
      0x7ffff7f54000     0x7ffff7fa0000    0x4c000   0x16a000 /usr/lib/x86_64-linux-gnu/libc-2.28.so                 
      0x7ffff7fa0000     0x7ffff7fa1000     0x1000   0x1b6000 /usr/lib/x86_64-linux-gnu/libc-2.28.so                 
      0x7ffff7fa1000     0x7ffff7fa5000     0x4000   0x1b6000 /usr/lib/x86_64-linux-gnu/libc-2.28.so                 
      0x7ffff7fa5000     0x7ffff7fa7000     0x2000   0x1ba000 /usr/lib/x86_64-linux-gnu/libc-2.28.so                 
      0x7ffff7fa7000     0x7ffff7fad000     0x6000        0x0                                                        
      0x7ffff7fd0000     0x7ffff7fd3000     0x3000        0x0 [vvar]                                                 
      0x7ffff7fd3000     0x7ffff7fd5000     0x2000        0x0 [vdso]                                                 
      0x7ffff7fd5000     0x7ffff7fd6000     0x1000        0x0 /usr/lib/x86_64-linux-gnu/ld-2.28.so                   
      0x7ffff7fd6000     0x7ffff7ff4000    0x1e000     0x1000 /usr/lib/x86_64-linux-gnu/ld-2.28.so                   
      0x7ffff7ff4000     0x7ffff7ffc000     0x8000    0x1f000 /usr/lib/x86_64-linux-gnu/ld-2.28.so                   
      0x7ffff7ffc000     0x7ffff7ffd000     0x1000    0x26000 /usr/lib/x86_64-linux-gnu/ld-2.28.so                   
      0x7ffff7ffd000     0x7ffff7ffe000     0x1000    0x27000 /usr/lib/x86_64-linux-gnu/ld-2.28.so                   
      0x7ffff7ffe000     0x7ffff7fff000     0x1000        0x0                                                        
      0x7ffffffde000     0x7ffffffff000    0x21000        0x0 [stack]
```

From this output, we can see that the function resides in a chunk of memory ranging from address 0x401000 to 0x402000. Let's go ahead and dump all that memory out.

```shell
pwndbg> dump binary memory data.bin 0x401000 0x402000
```

Now we have a data.bin file that contains the decrypted function.

## Patching

The next step is to patch the original binary with the decrypted data held within data.bin. To do that, we'll use another python script called "overwrite.py".

```python
#!/usr/bin/env python3
import sys

def stomp(binary: str, write_address: int, replacement: str):
    """Overwrites binary with data contained in replacement file
       Starting at write_address 
    """
    replacement_data = None
    with open(replacement, 'rb') as f:
        replacement_data = f.read(0x1000)

    with open(binary, 'rb+') as f:
        f.seek(write_address)
        f.write(replacement_data)

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: ./overwrite [binary] [write address] [replacement]")
        sys.exit(1)

    binary = sys.argv[1]

    write_address = sys.argv[2]
    try:
        write_address = int(sys.argv[2])        #encryption start address
    except ValueError:
        write_address = int(sys.argv[2], 16)

    replacement = sys.argv[3]
    stomp(binary, write_address, replacement)
```

This script takes in as arguments the original binary to be modified (arg 1), the address in the binary at which to write (arg 2), and the file containing the data to put there (arg 3).

This isn't really using any new methods from what we saw in the first post in this series. It opens the file containing the replacement data, and reads it into memory. It then opens the original binary file, seeks to the address we provided, and overwrites the data there with the replacement data.

We can now use this script to patch our binary

```shell
rgood@debian:~/Playground/self-decrypt$ ./overwrite.py main 0x1000 data.bin
```

You'll remember from part 1 that 0x1000 is where the data actually resides on disk, so this is where we will write the replacement data.

Now we can see that our binary contains the decrypted function while at rest

```shell
rgood@debian:~/Playground/self-decrypt$ objdump -D main -M intel| grep "encrypt_me>:" -A 8
0000000000401142 <encrypt_me>:
  401142:       55                      push   rbp
  401143:       48 89 e5                mov    rbp,rsp
  401146:       48 8d 3d b7 0e 00 00    lea    rdi,[rip+0xeb7]        # 402004 <_IO_stdin_used+0x4>
  40114d:       e8 ee fe ff ff          call   401040 <puts@plt>
  401152:       90                      nop
  401153:       5d                      pop    rbp
  401154:       c3                      ret  
```

In a larger more complex binary, having all of the functionality in a decrypted state like this would make static analysis much easier. Enabling analysts to gain a more in depth understanding of the sample's functionality without it needing to be detonated. 

## Encryption Removal

At this point, the binary is decrypted. However, if we attempt to run it we will get a crash.

```shell
rgood@debian:~/Playground/self-decrypt$ ./main 
Main function
Illegal instruction
```

This is because the binary is attempted to "decrypt" an already decrypted function. The result is a crash due to attempting to execute garbage instructions.

In this example, we can quickly patch this by NOPing out the xor instructions, as this will remove our simple encryption. NOP is an instruction that simply does nothing, and the hex code for it is 0x90. Replacing the encryption xor instruction with this will remove that logic cleanly.

Let's take at the main() function:

```shell
rgood@debian:~/Playground/self-decrypt$ objdump -D main -M intel| grep "main>:" -A 32
0000000000401155 <main>:
  401155:       55                      push   rbp
  401156:       48 89 e5                mov    rbp,rsp
  401159:       48 83 ec 20             sub    rsp,0x20
  40115d:       c7 45 ec 00 00 00 00    mov    DWORD PTR [rbp-0x14],0x0
  401164:       48 8d 3d aa 0e 00 00    lea    rdi,[rip+0xeaa]        # 402015 <_IO_stdin_used+0x15>
  40116b:       e8 d0 fe ff ff          call   401040 <puts@plt>
  401170:       48 8d 05 cb ff ff ff    lea    rax,[rip+0xffffffffffffffcb]        # 401142 <encrypt_me>
  401177:       25 00 f0 ff 00          and    eax,0xfff000
  40117c:       48 89 45 e0             mov    QWORD PTR [rbp-0x20],rax
  401180:       48 8b 45 e0             mov    rax,QWORD PTR [rbp-0x20]
  401184:       ba 07 00 00 00          mov    edx,0x7
  401189:       be 00 10 00 00          mov    esi,0x1000
  40118e:       48 89 c7                mov    rdi,rax
  401191:       e8 ba fe ff ff          call   401050 <mprotect@plt>
  401196:       89 45 ec                mov    DWORD PTR [rbp-0x14],eax
  401199:       83 7d ec 00             cmp    DWORD PTR [rbp-0x14],0x0
  40119d:       79 09                   jns    4011a8 <main+0x53>
  40119f:       e8 8c fe ff ff          call   401030 <__errno_location@plt>
  4011a4:       8b 00                   mov    eax,DWORD PTR [rax]
  4011a6:       eb 59                   jmp    401201 <main+0xac>
  4011a8:       48 8d 05 93 ff ff ff    lea    rax,[rip+0xffffffffffffff93]        # 401142 <encrypt_me>
  4011af:       48 89 45 f8             mov    QWORD PTR [rbp-0x8],rax
  4011b3:       48 8d 05 9b ff ff ff    lea    rax,[rip+0xffffffffffffff9b]        # 401155 <main>
  4011ba:       48 8d 50 ff             lea    rdx,[rax-0x1]
  4011be:       48 8d 05 7d ff ff ff    lea    rax,[rip+0xffffffffffffff7d]        # 401142 <encrypt_me>
  4011c5:       48 29 c2                sub    rdx,rax
  4011c8:       48 89 d0                mov    rax,rdx
  4011cb:       48 89 45 f0             mov    QWORD PTR [rbp-0x10],rax
  4011cf:       eb 1a                   jmp    4011eb <main+0x96>
  4011d1:       48 8b 45 f8             mov    rax,QWORD PTR [rbp-0x8]
  4011d5:       8b 00                   mov    eax,DWORD PTR [rax]
  4011d7:       34 fa                   xor    al,0xfa
```

At the end of the printed instructions, we can see our xor encryption culprit. The instructions to accomplish the xor is 0x34 0xfa, where 0x34 is the code for xor, and 0xfa is the encryption/decryption key.

Let's NOP out those instructions.

![Nop Out](/images/nop-out.gif)

We now have a decrypted sample that we can analyze/detonate as we desire!
