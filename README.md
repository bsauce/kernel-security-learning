# Kernel-Security-Learning

Sumup：There are some papers, articles and materials about kernel security.  

Keep updating...



## Paper

### 1.kernel exploit

（1）From collision to exploitation_ Unleashing Use-After-Free vulnerabilities in Linux Kernel-CCS2015

（2）Unleashing Use-Before-Initialization Vulnerabilities in the Linux Kernel Using Targeted Stack Spraying-NDSS2017 [note](https://www.jianshu.com/p/636db0e5d246)

（3）FUZE- Towards Facilitating Exploit Generation for Kernel Use-After-Free Vulnerabilities-usenix-2018 [note](https://www.jianshu.com/p/cfe7c9f7e852)

（4）KEPLER- Facilitating Control-flow Hijacking Primitive Evaluation for Linux Kernel Vulnerabilities-usenix2019

（5）SLAKE- Facilitating Slab Manipulation for Exploiting Vulnerabilities in the Linux Kernel-CCS2019 [note](https://www.jianshu.com/p/d731cd87c6f4)

### 2.kernel fuzz

（1）QSEE TrustZone Kernel Integer Overflow-Black hat 2014

（2）SKI：Exposing Kernel Concurrency Bugs through Systematic Schedule Exploration-usenix 2014

（3）UniSan- Proactive Kernel Memory Initialization to Eliminate Data Leakages-CCS2016

（4）CAB-Fuzz：Practical Concolic Testing Techniques for {COTS} Operating Systems-USENIX-2017

（5）DIFUZE- Interface Aware Fuzzing for Kernel Drivers-CCS-2017 [note](https://www.jianshu.com/p/670b141d1b8d)

（6）Digtool- A Virtualization-Based Framework for Detecting Kernel Vulnerabilities-usenix-2017 [note](https://www.jianshu.com/p/3cc85231657d)

（7）How Double-Fetch Situations turn into DoubleFetch-usenix-2017

（8）DR. CHECKER- A Soundy Analysis for Linux Kernel Drivers-usenix-2017

（9）kAFL- Hardware-Assisted Feedback Fuzzing for OS Kernels-usenix-2017 [note](https://www.jianshu.com/u/cd49be7bd6b5)

（10）DEADLINE-Precise and Scalable Detection of Double-Fetch Bugs in OS Kernels-sp2018 [note](https://www.jianshu.com/p/e4084b2c7c16)

（11）Check It Again- Detecting Lacking-Recheck Bugs in OS Kernels-CCS-2018 [note](https://www.jianshu.com/p/2f8df6082b1d)

（12）MoonShine：Optimizing OS Fuzzer Seed Selection with Trace Distillation-USENUX2018 [note](https://www.jianshu.com/p/7e90ad222acf)

（13）LBM- A Security Framework for Peripherals within the Linux Kernel-SP2019

（14）Razzer：Finding Kernel Race Bugs through Fuzzing-SP-2019 [note](https://www.jianshu.com/p/43ced9660257)

（15）Unicorefuzz- On the Viability of Emulation for Kernelspace Fuzzing-woot19

（16）Detecting Concurrency Memory Corruption Vulnerabilities-fse19

（17）Fuzzing File Systems via Two-Dimensional Input Space Exploration-sp2019 [note](https://www.jianshu.com/p/23c3e41254b6)

（18）Detecting Missing-Check Bugs via Semantic- and Context-Aware Criticalness and Constraints Inferences-usenix2019

（19）PeriScope：An Effective Probing and Fuzzing Framework for the Hardware-OS Boundary-NDSS2019 [note](https://www.jianshu.com/p/34568906d900)

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



## CVE

1. [Linux kernel 4.20 BPF 整数溢出漏洞分析](https://www.cnblogs.com/bsauce/p/11560224.html)
2. [【CVE-2017-16995】Linux ebpf模块整数扩展问题导致提权漏洞分析](https://www.cnblogs.com/bsauce/p/11583310.html)
3. [【CVE-2017-7184】Linux xfrm模块越界读写提权漏洞分析](https://www.cnblogs.com/bsauce/p/11634185.html)



## Tool



## Debugging & other techniques

1. [linux双机调试](https://www.cnblogs.com/bsauce/p/11634162.html)
2. [linux内核漏洞利用初探（1）：环境配置](https://blog.csdn.net/panhewu9919/article/details/99438304)
3. [【linux内核调试】SystemTap使用技巧](https://blog.csdn.net/panhewu9919/article/details/103113711)
4. [【Linux内核调试】使用Ftrace来Hook linux内核函数](https://www.jianshu.com/p/bf70a262787e)
5. [【linux内核调试】ftrace/kprobes/SystemTap内核调试方法对比](https://www.jianshu.com/p/285c91c97c28)
6. [【KVM】KVM学习—实现自己的内核](https://www.jianshu.com/p/5ec4507e9be0)




