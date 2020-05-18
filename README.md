# Kernel-Security-Learning

Sumup：There are some papers, articles and materials about kernel security.  

Keep updating...



---

## Paper

### 1.kernel exploit

（1）2015-CCS：From collision to exploitation_ Unleashing Use-After-Free vulnerabilities in Linux Kernel

（2）2017-NDSS：Unleashing Use-Before-Initialization Vulnerabilities in the Linux Kernel Using Targeted Stack Spraying [note](https://www.jianshu.com/p/636db0e5d246)

（3）2018-USENIX：FUZE-Towards Facilitating Exploit Generation for Kernel Use-After-Free Vulnerabilities [note](https://www.jianshu.com/p/cfe7c9f7e852)

（4）2019-USENIX：KEPLER-Facilitating Control-flow Hijacking Primitive Evaluation for Linux Kernel Vulnerabilities [note](https://www.jianshu.com/p/53570db6fcba)

（5）2019-CCS：SLAKE-Facilitating Slab Manipulation for Exploiting Vulnerabilities in the Linux Kernel-CCS2019 [note](https://www.jianshu.com/p/d731cd87c6f4)

（6）2020-USENIX：[KOOBE: Towards Facilitating Exploit Generation of Kernel Out-Of-Bounds Write Vulnerabilities](https://www.usenix.org/conference/usenixsecurity20/presentation/chen-weiteng) [note](https://www.jianshu.com/p/24cb664a2811)

### 2.kernel fuzz

（1）2014-Black Hat：QSEE TrustZone Kernel Integer Overflow

（2）2014-USENIX：SKI：Exposing Kernel Concurrency Bugs through Systematic Schedule Exploration

（3）2016-USENIX：UniSan-Proactive Kernel Memory Initialization to Eliminate Data Leakages

（4）2017-USENIX：CAB-Fuzz：Practical Concolic Testing Techniques for {COTS} Operating Systems

（5）2017-CCS：DIFUZE-Interface Aware Fuzzing for Kernel Drivers [note](https://www.jianshu.com/p/670b141d1b8d)

（6）2017-USENIX：Digtool- A Virtualization-Based Framework for Detecting Kernel Vulnerabilities-usenix [note](https://www.jianshu.com/p/3cc85231657d)

（7）2017-USENIX：How Double-Fetch Situations turn into DoubleFetch

（8）2017-USENIX：DR. CHECKER- A Soundy Analysis for Linux Kernel Drivers

（9）2017-USENIX：kAFL- Hardware-Assisted Feedback Fuzzing for OS Kernels-usenix [note](https://www.jianshu.com/u/cd49be7bd6b5)

（10）2018-S&P：DEADLINE-Precise and Scalable Detection of Double-Fetch Bugs in OS Kernels [note](https://www.jianshu.com/p/e4084b2c7c16)

（11）2018-CCS：Check It Again- Detecting Lacking-Recheck Bugs in OS Kernels [note](https://www.jianshu.com/p/2f8df6082b1d)

（12）2018-USENIX：MoonShine：Optimizing OS Fuzzer Seed Selection with Trace Distillation [note](https://www.jianshu.com/p/7e90ad222acf)

（13）2018-NDSS：K-Miner: Uncovering Memory Corruption in Linux [note](https://blog.csdn.net/u012332816/article/details/79795643)

（14）2019-S&P：LBM- A Security Framework for Peripherals within the Linux Kernel

（15）2019-S&P：Razzer：Finding Kernel Race Bugs through Fuzzing [note](https://www.jianshu.com/p/43ced9660257)

（16）2019-WOOT：Unicorefuzz- On the Viability of Emulation for Kernelspace Fuzzing

（17）2019-FSE：Detecting Concurrency Memory Corruption Vulnerabilities

（18）2019-S&P：Fuzzing File Systems via Two-Dimensional Input Space Exploration [note](https://www.jianshu.com/p/23c3e41254b6)

（19）2019-USENIX：Detecting Missing-Check Bugs via Semantic- and Context-Aware Criticalness and Constraints Inferences

（20）2019-NDSS：PeriScope：An Effective Probing and Fuzzing Framework for the Hardware-OS Boundary [note](https://www.jianshu.com/p/34568906d900)

（21）2020-NDSS：[HFL: Hybrid Fuzzing on the Linux Kernel](https://www.ndss-symposium.org/ndss-paper/hfl-hybrid-fuzzing-on-the-linux-kernel/)

（22）2020-S&P：[Krace: Data Race Fuzzing for Kernel File Systems](https://www.computer.org/csdl/proceedings-article/sp/2020/349700b568/1iqVRYHTi24)

### 3.kernel defense

2017-USENIX：[Can’t Touch This: Software-only Mitigation against Rowhammer Attacks targeting Kernel Memory](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/brasser)

2017-USENIX：[Oscar: A Practical Page-Permissions-Based Scheme for Thwarting Dangling Pointers](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/dang)

2019-USENIX：[PeX: A Permission Check Analysis Framework for Linux Kernel](https://www.usenix.org/conference/usenixsecurity19/presentation/zhang-tong)

2019-USENIX：[ERIM: Secure, Efficient In-process Isolation with Protection Keys (MPK)](https://www.usenix.org/conference/usenixsecurity19/presentation/vahldiek-oberwagner)

2019-USENIX：[SafeHidden: An Efficient and Secure Information Hiding Technique Using Re-randomization](https://www.usenix.org/conference/usenixsecurity19/presentation/wang)

2017-USENIX：[Oscar: A Practical Page-Permissions-Based Scheme for Thwarting Dangling Pointers](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/dang)

2017-CCS：[kRˆX: Comprehensive Kernel Protection Against Just-In-Time Code Reuse](http://www.cs.columbia.edu/~theofilos/files/papers/2017/krx.pdf)  [[slides](http://www.cs.columbia.edu/~theofilos/files/slides/krx.pdf)]

2020-S&P：[xMP: Selective Memory Protection for Kernel and User Space](https://www.computer.org/csdl/proceedings-article/sp/2020/349700a603/1iqVRnCoPjq)

2020-S&P：[SEIMI: Efficient and Secure SMAP-Enabled Intra-process Memory Isolation](https://www.computer.org/csdl/proceedings-article/sp/2020/349700b332/1iqVRPB1xbG)

---

### 4. Android

2020-USEINX：[Automatic Hot Patch Generation for Android Kernels](https://www.usenix.org/conference/usenixsecurity20/presentation/xu)—自动给安卓打补丁



---

## CTF

1. [linux内核漏洞利用初探（1）：环境配置](https://blog.csdn.net/panhewu9919/article/details/99438304)
2. [linux内核漏洞利用初探（2）：demo-null_dereference](https://blog.csdn.net/panhewu9919/article/details/99441712)
3. [linux内核漏洞利用初探（3）：demo-stack_overflow](https://blog.csdn.net/panhewu9919/article/details/99485487)
4. [【Linux内核漏洞利用】2018强网杯core_栈溢出](https://www.jianshu.com/p/8d950a9d8974)
5. [【Linux内核漏洞利用】CISCN2017-babydriver_UAF漏洞](https://www.jianshu.com/p/5dbdabba7e75)
6. [【Linux内核漏洞利用】0CTF2018-baby-double-fetch](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/kernel/double-fetch/)
7. [【Linux内核漏洞利用】强网杯2018-solid_core-任意读写](https://www.jianshu.com/p/3d707fac499a)
8. [【linux内核漏洞利用】StringIPC—从任意读写到权限提升三种方法](https://www.jianshu.com/p/07994f8b2bb0)
9. [【linux内核漏洞利用】STARCTF 2019 hackme—call_usermodehelper提权路径变量总结](https://www.jianshu.com/p/a2259cd3e79e)
10. [【linux内核漏洞利用】WCTF 2018 klist—竞争UAF-pipe堆喷](https://blog.csdn.net/panhewu9919/article/details/100728934)
11. [【linux内核漏洞利用】TokyoWesternsCTF-2019-gnote Double-Fetch](https://blog.csdn.net/panhewu9919/article/details/100891770)
12. [【linux内核userfaultfd使用】Balsn CTF 2019 - KrazyNote](https://www.jianshu.com/p/a70a358ec02c)
13. [linux内核提权系列教程（1）：堆喷射函数sendmsg与msgsend利用](https://www.jianshu.com/p/5583657cfd25)
14. [linux内核提权系列教程（2）：任意地址读写到提权的4种方法](https://www.jianshu.com/p/fef2377f6a31)
15. [linux内核提权系列教程（3）：栈变量未初始化漏洞](https://www.jianshu.com/p/b28b964b9243)
16. [【linux内核漏洞利用】ret2dir利用方法](https://www.jianshu.com/p/3c662b6163a7)



---

## CVE

1. [Linux kernel 4.20 BPF 整数溢出漏洞分析](https://www.cnblogs.com/bsauce/p/11560224.html)
2. [【CVE-2017-16995】Linux ebpf模块整数扩展问题导致提权漏洞分析](https://www.cnblogs.com/bsauce/p/11583310.html)
3. [【CVE-2017-7184】Linux xfrm模块越界读写提权漏洞分析](https://www.cnblogs.com/bsauce/p/11634185.html)



---

## Tool



---

## Debugging & other techniques

1. [linux双机调试](https://www.cnblogs.com/bsauce/p/11634162.html)
2. [linux内核漏洞利用初探（1）：环境配置](https://blog.csdn.net/panhewu9919/article/details/99438304)
3. [【linux内核调试】SystemTap使用技巧](https://blog.csdn.net/panhewu9919/article/details/103113711)
4. [【linux内核调试】使用Ftrace来Hook linux内核函数](https://www.jianshu.com/p/bf70a262787e)
5. [【linux内核调试】ftrace/kprobes/SystemTap内核调试方法对比](https://www.jianshu.com/p/285c91c97c28)
6. [【KVM】KVM学习—实现自己的内核](https://www.jianshu.com/p/5ec4507e9be0)




