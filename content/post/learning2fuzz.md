---
title: "Fuzzing Around: How I Learned to Fuzz and Found 3 CVEs"
date: 2022-06-08T16:49:57-05:00
draft: false
---

## Introduction

I've been doing software development and cyber security related work for a decent time now, and figured it was finally time to find some real vulnerabilities in well known native applications. Of course, I'm far too lazy to manually reverse engineer things myself, so I decided to learn how to fuzz. As an added bonus, you get to put cool stuff on your terminal that makes it look like you know what you're doing!

![AFL Fuzzing](/images/afl.gif)

I was able to pick up the basics pretty quickly, and even found 3 CVEs in the process. Now it's time to document my processes (hopefully I haven't already forgotten) so that I remember how to do this in future. Maybe someone else will benefit from this too!

## Picking a Target

In order to properly motivate myself, I wanted to find a target where I was likely to get some wins. I wanted something that was open source, and had a lot of code doing heavy processing of user provided input.

While I was hunting for a target, I stumbled on the platform [huntr](https://huntr.dev/). I had never been very interested in bug bounty, as it typically focuses on web vulnerabilities. This platform provides potential bounties for any github repository (given it's popular enough). It also greatly streamlines the process of receiving a CVE for relevant targets/vulnerabilities. 

I started sorting through previous bug reports to see if any were based on traditional systems programming languages (C/C++). Pretty quickly, I saw a number of reports for [Vim](https://www.vim.org/). This caught my eye, as I use Vim on a daily basis and think it's a great tool to increase productivity. It's definitely better than Emacs ;)

## Preparing to Fuzz

First we'll need to grab and build afl++.

```shell
git clone git@github.com:AFLplusplus/AFLplusplus.git
cd AFLplusplus
sudo make install
```

I had to help AFL find the proper llvm-config. If you have issues with your build try this:
```shell
LLVM_CONFIG=llvm-config-11 sudo make install
```

Now that I had my target picked out, I needed to clone and build it as well.

```shell
git clone git@github.com:vim/vim.git
cd vim
make
```

After taking a quick look at the results, I realized I had no symbols! This wasn't going to work, so I recompiled to add them in.

```shell
make distclean
CFLAGS="-g" ./configure
make
```

In order to provide useful input, we'll use source files containing ex commands (typically you enter these by hitting escape and prepending them with a colon ex: ':wq' to save and quit). To do this, we'll use the following flags:

* -e: enables ex mode so that all input is treated as ex commands.
* -S: allows us to provide commands via a source file, making fuzzing easier.

The last couple things we'll need to do is create input and output directories. The input directory will contain our initial [corpus](https://google.github.io/clusterfuzz/reference/glossary/#corpus), and the output directory will results. These results include hangs, crashes, and additional corpus additions the fuzzer discovers.

I'll be storing these in shared memory so I don't have to deal with tons of files being created on disk.

```shell
mkdir /dev/shm/input && mkdir /dev/shm/output
echo "stuff" > /dev/shm/input/stuff
```

Now let's run our fuzzer!

```shell
afl-fuzz -i /dev/shm/input -o /dev/shm/output -M main -- ./src/vim -e -S @@
[-] PROGRAM ABORT : No instrumentation detected
```

Looks like that didn't work. AFL isn't able to properly fuzz the target as it's not "instrumented" yet. This means we haven't compiled the target properly so that additional logic is added to inform the fuzzer when various function paths are reached. 

To fix this we'll want to use the afl-clang-lto compiler to build the target, as that's what the afl++ repo recommends.

```shell
cd vim
make distclean
CC=afl-clang-lto CFLAGS="-g" ./configure
make
```

Now we should be able to start fuzzing...

## Fuzzing Vim
