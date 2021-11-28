---
title: "ELF Science Part 2"
date: 2021-11-27T19:30:17-06:00
draft: true
---

## Introduction

This post is a follow up to [part 1](/post/elf_science_p1/).

In the last post, we demonstrated a basic method for creating a self-decrypting binary. This is a common technique in many malware variants to add difficulty to the reverse engineering process.

Inspired by some feedback from [@marisa_hacks](https://twitter.com/marisa_hacks), this post will focus on dismantling our previous efforts.

We'll perform dynamic analysis on the binary in order to step through to the point at which it is decrypted. At this point we will dump the process so that we have the decrypted version for static analysis. To take things a step further, we'll then strip out the encryption logic.

## Dynamic Analysis

show encrypted unreadable form

step through showing it in its decrypted state

dump 401000-402000 to copy decrypted data out

write dumped data to binary at 1000-2000 to create decrypted version (will need to create python script for this)

show static analysis

remove encryption logic by replacing with NOPs