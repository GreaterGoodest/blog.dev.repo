---
title: "ELF Science Part 2"
date: 2021-11-27T19:30:17-06:00
draft: true
---

## Introduction

This post is a follow up to [part 1](/post/elf_science_p1/).

In the last post, we demonstrated a basic method for creating a self-decrypting binary. This is a common technique in many malware variants to add difficulty to the reverse engineering process.

Inspired by some feedback from [@marisa_hacks](https://twitter.com/marisa_hacks), this post will focus on dismantling our previous efforts.

We'll perform dynamic analysis on the binary in order to step through to the point at which it is decrypted. Once we have the binary in it's decrypted form, we will dump out the executable portion of intrest. We will then overwrite the binary with this decrypted data, allowing for better static analysis in future. To take things a step further, we'll then strip out the encryption logic.

## Dynamic Analysis and Decryption

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

TODO:
- step through showing it in its decrypted state
- dump 401000-402000 to copy decrypted data out
- write dumped data to binary at 1000-2000 to create decrypted version (will need to create python script for this)
- show static analysis
- remove encryption logic by replacing with NOPs