ftrace-hook
===========

Linux kernel module demonstrating usage of **ftrace** framework for function
*hooking*: as in executing arbitrary code *around* the hooked function.

The code is licensed under GPLv2_.

.. _GPLv2: LICENSE

How to build
------------

 Please consider using **a virtual machine** (VirtulBox, VMWare, QEMU, etc.)
 for experiments. The (unchanged) module is totally harmless and should not
 affect your system stability. But just in case: you are loading it at your
 own risk. Don't kill your own machine or production environment by accident.

Make sure you have installed GCC and Linux kernel headers for your kernel.
For Debian-based systems::

    $ sudo apt install build-essential linux-headers-$(uname -r)

Build the kernel module::

    $ cd ftrace-hook
    $ make
    make -C /lib/modules/4.9.0-5-amd64/build M=/home/ilammy/dev/ftrace-hook modules
    make[1]: Entering directory '/usr/src/linux-headers-4.9.0-5-amd64'
      CC [M]  /home/ilammy/dev/ftrace-hook/ftrace_hook.o
      Building modules, stage 2.
      MODPOST 1 modules
      CC      /home/ilammy/dev/ftrace-hook/ftrace_hook.mod.o
      LD [M]  /home/ilammy/dev/ftrace-hook/ftrace_hook.ko
    make[1]: Leaving directory '/usr/src/linux-headers-4.9.0-5-amd64'

This should build the module for the kernel you are currently running.
You can load it into your system, experiment, and unload the module
like this::

    $ sudo insmod ftrace_hook.ko

    $ ls -l
    total 736
    -rw-r--r-- 1 ilammy ilammy   6765 Jun  3 11:22 ftrace_hook.c
    -rw-r--r-- 1 ilammy ilammy 349152 Jun  3 15:27 ftrace_hook.ko
    -rw-r--r-- 1 ilammy ilammy   1245 Jun  3 15:27 ftrace_hook.mod.c
    -rw-r--r-- 1 ilammy ilammy 144600 Jun  3 15:27 ftrace_hook.mod.o
    -rw-r--r-- 1 ilammy ilammy 208360 Jun  3 15:27 ftrace_hook.o
    -rw-r--r-- 1 ilammy ilammy  18092 Jun  3 09:34 LICENSE
    -rw-r--r-- 1 ilammy ilammy    170 Jun  3 09:34 Makefile
    -rw-r--r-- 1 ilammy ilammy     51 Jun  3 15:27 modules.order
    -rw-r--r-- 1 ilammy ilammy      0 Jun  3 15:27 Module.symvers
    -rw-r--r-- 1 ilammy ilammy   1081 Jun  3 15:26 README.rst

    $ sudo rmmod ftrace_hook

Kernel logs can be viewed like this::

    $ sudo dmesg --follow
    [  239.217934] ftrace_hook: module loaded
    [  242.531043] ftrace_hook: clone() before
    [  242.531253] ftrace_hook: clone() after: 2674
    [  242.531665] ftrace_hook: execve() before: /bin/ls
    [  242.532150] ftrace_hook: execve() after: 0
    [  257.522832] ftrace_hook: clone() before
    [  257.523087] ftrace_hook: clone() after: 2675
    [  257.523522] ftrace_hook: execve() before: /usr/bin/sudo
    [  257.524002] ftrace_hook: execve() after: 0
    [  257.531963] ftrace_hook: clone() before
    [  257.532194] ftrace_hook: clone() after: 2676
    [  257.533332] ftrace_hook: execve() before: /sbin/rmmod
    [  257.533714] ftrace_hook: execve() after: 0
    [  257.560086] ftrace_hook: module unloaded
