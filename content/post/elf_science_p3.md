---
title: "ELF Science Part 3"
date: 2021-12-17T14:57:52-06:00
draft: true
---

## Introduction

This post is part of a three part series (so far) 
- [Part 1](/post/elf_science_p1/)
- [Part 2](/post/elf_science_p2/)

In the last edition of ELF Science, we defeated our encryption methodology by running the binary in a debugger, setting a breakpoint after self-decryption is complete, and dumping the decrypted memory. We then re-wrote the binary using these decrypted instructions, and NOP'd out the xor encryption method.

In this edition, we'll return to our scheming ways and discuss additional ways to frustrate would be reversers. 

Firstly, we'll check to see if we're are being run in a debugger. If that's the case, we'll immediately exit. After that, we'll check if we are running in a virtualized environment (VMware, etc.). Virtualized environments are commonly used to detonate malware, as they reduce the risk to the host system. Of course, you wouldn't want to perform this check if you're attacking an EC2 instance or something similar. If we detect that the host system is virtualized, this will also lead to early termination. Quite devious.

Of course, once we've implemented these new features we will also explore how easily they can be defeated. 

