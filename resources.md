---
layout: page
title: "Resources"
permalink: /resources/
---

This page lists resources that I've found helpful in the past.

## Reverse Engineering

### Ghidra

- [2019] Working with Ghidra's P-Code to Identify Vulnerable Function Calls
	- Describes working with Ghidra's IL called P-Code.
	- [https://www.riverloopsecurity.com/blog/2019/05/pcode/]()
	- [https://web.archive.org/web/20201208232408/https://www.riverloopsecurity.com/blog/2019/05/pcode/]()
- [2019] Software Reverse Engineering with Ghidra
	- A video series that walks through reverse engineering C++ binaries in Ghidra.
	- [https://youtu.be/4v8WkHmSFUU]()

## Android

### Bootloader

- [2017] Reverse Engineering Samsung S6 SBOOT
	- A series by Quarkslab that describes how to reverse engineer Samsung's SBOOT bootloader.
	- [https://blog.quarkslab.com/reverse-engineering-samsung-s6-sboot-part-i.html]()
	- [https://web.archive.org/web/20201111195637/https://blog.quarkslab.com/reverse-engineering-samsung-s6-sboot-part-i.html]()

- [2014] Reverse Engineering Android's Aboot
	- Describes how to reverse engineering bootloaders on the Nexus 5, Galaxy S5, and Fire HDX.
	- [http://www.newandroidbook.com/Articles/aboot.html]()
	- [https://web.archive.org/web/20201227165102/http://www.newandroidbook.com/Articles/aboot.html]()

### Rooting via Unlocked Bootloader

- [2017] Android Rooting: An Arms Race between Evasion and Detection
	- The history of Android rooting tools, how they work, and how apps are detecting them.
	- [https://www.hindawi.com/journals/scn/2017/4121765/]()
	- [https://web.archive.org/web/20201227163141if_/https://www.hindawi.com/journals/scn/2017/4121765/]()

### Samsung's Mitigations

- [2020] A Samsung RKP Compendium
	- Pretty much lifts Samsung's hypervisor (called uh) to C and walks through it. It also describes a patched vulnerabities to get EL2 read/write.
	- https://www.longterm.io/samsung_rkp.html
	- https://web.archive.org/web/20210106020249/https://www.longterm.io/samsung_rkp.html

- [2017] Defeating Samsung KNOX with Zero Privilege
	- Describes bypassing Samsung's KNOX mitigations using CVE-2016-6787.
	- [https://www.youtube.com/watch?v=6bPuEfHSYOc]()
	- [https://www.blackhat.com/docs/us-17/thursday/us-17-Shen-Defeating-Samsung-KNOX-With-Zero-Privilege-wp.pdf]()
	- [https://web.archive.org/web/20190630180019/https://www.blackhat.com/docs/us-17/thursday/us-17-Shen-Defeating-Samsung-KNOX-With-Zero-Privilege-wp.pdf]()

### Binder

- [2020] Exploiting a Single Instruction Race Condition in Binder
	- Describes how they exploited a race condition in Binder (CVE-2020-0423) to achieve LPE.
	- [https://www.longterm.io/cve-2020-0423.html]()
	- [https://web.archive.org/web/20201227155716/https://www.longterm.io/cve-2020-0423.html]()

- [2020] Android Kernel Exploitation (Free Workshop)
	- A free workshop that walks readers through exploiting CVE-2019-2215, a.k.a. Bad Binder, on an Android VM.
	- [https://cloudfuzz.github.io/android-kernel-exploitation/]()
	- [https://web.archive.org/web/20201227160253/https://cloudfuzz.github.io/android-kernel-exploitation/]()

## Linux Kernel

### KASLR

- [2020] Exploiting Uses of Uninitialized Stack Variables in Linux Kernels to Leak Kernel Pointers
	- Describes a method for computing a kernel stack leak's offset. Introduces a primitive to spray pointers onto the kernel stack using a small BPF program. Describes how to leak pointers with very small leaks (e.g. 4 byte leaks on 64-bit kernels).
	- [https://www.usenix.org/system/files/woot20-paper-cho.pdf]()
	- [https://web.archive.org/web/20201227154246/https://www.usenix.org/system/files/woot20-paper-cho.pdf]()
