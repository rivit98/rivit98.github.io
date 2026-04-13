---
title: "Open-sourcing community CTF challenges"
description: Community CTF puzzles I open-sourced (pwn, re, misc, crypto) and a short stats summary
date: 2026-04-13T12:00:00Z
categories:
    - ctf
    - challenges
---

I [open-sourced](https://github.com/rivit98/ctf-challenges/tree/master/community) a set of community CTF challenges I created for [CTFlearn](https://ctflearn.com/). The collection is intentionally pragmatic: small, self-contained puzzles you can run locally (Docker is provided), iterate on, and learn from.

## What is in the repository

The repository contains 20+ challenges across four categories:

- pwn: the largest category — small networked binaries and local pwn problems covering memory corruption, information leaks, non-standard allocators, and ROP-style exploitation.
- reversing: reverse-engineering puzzles and binary-analysis tasks.
- misc: utility and puzzle-style problems that do not fit the categories above.
- crypto: a small, crypto-related puzzle.

All challenges ship with simple infrastructure to run them locally: Dockerfiles, a compose profile, solver scripts, and a short README. The repository README includes quick-start hints.

## Stats

I stopped hosting the community challenges on 30.12.2025 due to time constraints and rising maintenance costs. The site included a public scoreboard — the numbers below are snapshot as of 30.12.2025.

Top solved challenges (by solves):

- Accumulator — 1,077 solves
- Zippy.zip — 689 solves
- Leak me — 442 solves
- Domain name resolver — 344 solves
- Positive challenge — 326 solves

Total solves by category (all challenges combined):

- pwn: 3,245 total solves
- crypto: 689 total solves
- misc: 219 total solves
- reversing: 90 total solves

All challenges combined: 4,243 solves.


## Why I published them

I published them to enable low-friction sharing, since a public repository is easier to maintain than hosting long-lived services. When hosting costs and maintenance time became unreasonable, I shut down the hosted instances but left the repository available. I hope the collection can be useful for CTF players, educators, and anyone interested in learning about CTF challenges. The puzzles are designed to be approachable and educational.

