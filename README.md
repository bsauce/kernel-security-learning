# Kernel-Security-Learning

Anything about kernel security. CTF kernel pwn & kernel exploit, kernel fuzz and kernel defense paper & kernel debugging technique & kernel CVE debug. 

Keep updating...

---

## 1. CTF

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
17. [【内核漏洞利用】绕过CONFIG_SLAB_FREELIST_HARDENED防护—kernoob两种解法](https://blog.csdn.net/panhewu9919/article/details/111839950)



---

## 2. Paper

#### （1）kernel exploit

1. 2014-USENIX：[ret2dir: Rethinking Kernel Isolation](https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/kemerlis)
2. 2015-CCS：[From collision to exploitation_ Unleashing Use-After-Free vulnerabilities in Linux Kernel](https://gts3.org/~wen/assets/papers/xu:collision-slides.pdf)
3. 2016-CCS：[Prefetch Side-Channel Attacks - Bypassing SMAP and Kernel ASLR](https://doi.org/10.1145/2976749.2978356)
4. 2016-CCS：[Breaking Kernel Address Space Layout Randomization with Intel TSX](https://doi.org/10.1145/2976749.2978321)
5. 2017-CCS：[SemFuzz: Semantics-based Automatic Generation of Proof-of-Concept Exploits](https://acmccs.github.io/papers/p2139-youA.pdf)
6. 2017-NDSS：[Unleashing Use-Before-Initialization Vulnerabilities in the Linux Kernel Using Targeted Stack Spraying](https://www-users.cs.umn.edu/~kjlu/papers/tss.pdf) — 【[note](https://www.jianshu.com/p/636db0e5d246)】
7. 2018-USENIX：[FUZE-Towards Facilitating Exploit Generation for Kernel Use-After-Free Vulnerabilities](https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-wu_0.pdf) — 【[note](https://www.jianshu.com/p/cfe7c9f7e852)】【[tool-FUZE](https://github.com/ww9210/Linux_kernel_exploits)】
8. 2019-USENIX：[KEPLER-Facilitating Control-flow Hijacking Primitive Evaluation for Linux Kernel Vulnerabilities](https://www.usenix.org/system/files/sec19-wu-wei.pdf) — 【[note](https://www.jianshu.com/p/53570db6fcba)】【[tool-KEPLER](https://github.com/ww9210/kepler-cfhp)】
9. 2019-CCS：[SLAKE-Facilitating Slab Manipulation for Exploiting Vulnerabilities in the Linux Kernel](http://www.personal.psu.edu/yxc431/publications/SLAKE.pdf) — 【[note](https://www.jianshu.com/p/d731cd87c6f4)】【[tool-SLAKE](https://github.com/chenyueqi/SLAKE)】
10. 2020-USENIX：[KOOBE: Towards Facilitating Exploit Generation of Kernel Out-Of-Bounds Write Vulnerabilities](https://www.usenix.org/conference/usenixsecurity20/presentation/chen-weiteng) — 【[note](https://www.jianshu.com/p/24cb664a2811)】【[note2](https://securitygossip.com/blog/2020/04/03/koobe-towards-facilitating-exploit-generation-of-kernel-out-of-bounds-write-vulnerabilities/)】【[tool-KOOBE](https://github.com/seclab-ucr/KOOBE)】
11. 2020-CCS：[A Systematic Study of Elastic Objects in Kernel Exploitation](http://www.personal.psu.edu/yxc431/publications/ELOISE.pdf) — 【[note](https://www.jianshu.com/p/982b42f3671f)】【[note2](https://securitygossip.com/blog/2020/11/03/a-systematic-study-of-elastic-objects-in-kernel-exploitation/)】【[tool-ELOISE](https://github.com/chenyueqi/w2l)】
12. 2020-WOOT：[Exploiting Uses of Uninitialized Stack Variables in Linux Kernels to Leak Kernel Pointers](https://sefcom.asu.edu/publications/leak-kptr-woot20.pdf)
13. 2021-USENIX：[ExpRace: Exploiting Kernel Races through Raising Interrupts](https://www.usenix.org/conference/usenixsecurity21/presentation/lee-yoochan) — 【[note](https://bsauce.github.io/2021/05/26/USENIX-2021-EXPRACE/)】
14. 2021-CCS：[Demons in the Shared Kernel: Abstract Resource Attacks Against OS-level Virtualization](https://wenboshen.org/assets/papers/LogicalDoS.pdf) — 【[note](https://mp.weixin.qq.com/s/9qYP2jKvCWymjfUWVWOlCg)】

#### （2）kernel vulerability detection

1. 2012-OSDI：[Improving integer security for systems with KINT](https://www.usenix.org/conference/osdi12/technical-sessions/presentation/wang)
2. 2014-Black Hat：[QSEE TrustZone Kernel Integer Overflow](https://paper.bobylive.com/Meeting_Papers/BlackHat/USA-2014/us-14-Rosenberg-Reflections-On-Trusting-TrustZone-WP.pdf)
3. 2014-USENIX：[Static Analysis of Variability in System Software - The 90, 000 #ifdefs Issue](https://www.usenix.org/conference/atc14/technical-sessions/presentation/tartler)
4. 2014-OSDI：[SKI：Exposing Kernel Concurrency Bugs through Systematic Schedule Exploration](https://www.usenix.org/system/files/conference/osdi14/osdi14-paper-fonseca.pdf)
5. 2015-SOSP：[Cross-checking semantic correctness: The case of finding file system bugs](https://lifeasageek.github.io/papers/min-juxta.pdf) — 【[tool-JUXTA](https://github.com/sslab-gatech/juxta)】
6. 2016-USENIX：[UniSan-Proactive Kernel Memory Initialization to Eliminate Data Leakages](https://dl.acm.org/doi/pdf/10.1145/2976749.2978366) — 【[note](http://www.inforsec.org/wp/?p=1416)】【[tool-unisan](https://github.com/sslab-gatech/unisan)】
7. 2016-USENIX：[APISan: Sanitizing API Usages through Semantic Cross-Checking](https://pdfs.semanticscholar.org/29c2/42b2b73c376a61344877d5488f33e066ecc8.pdf?_ga=2.254762891.2010008061.1593351615-150437918.1586869794) — 【[tool-apisan](https://github.com/sslab-gatech/apisan)】
8. 2017-EUROSYS：[DangSan - Scalable Use-after-free Detection](https://doi.org/10.1145/3064176.3064211) — 【[tool-dangsan](https://github.com/vusec/dangsan)】
9. 2017-USENIX-ATC：[CAB-Fuzz：Practical Concolic Testing Techniques for {COTS} Operating Systems](https://www.usenix.org/system/files/conference/atc17/atc17-kim.pdf)
10. 2017-CCS：[DIFUZE-Interface Aware Fuzzing for Kernel Drivers](https://acmccs.github.io/papers/p2123-corinaA.pdf) — 【[note](https://www.jianshu.com/p/670b141d1b8d)】【[tool-difuze](https://github.com/ucsb-seclab/difuze)】
11. 2017-USENIX：[Digtool- A Virtualization-Based Framework for Detecting Kernel Vulnerabilities-usenix](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-pan.pdf) — 【[note](https://www.jianshu.com/p/3cc85231657d)】【[note2](https://mp.weixin.qq.com/s/RFWqx0LXWuHcJNbb8lrjFA)】【[note3](http://yama0xff.com/2019/02/15/Digtool-A-Virtualization-Based-Framework-for-Detecting-Kernel-Vulnerabilities/)】【[note4](https://securitygossip.com/blog/2018/10/09/digtool-a-virtualization-based-framework-for-detecting-kernel-vulnerabilities/)】
12. 2017-USENIX：[How Double-Fetch Situations turn into DoubleFetch](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-wang.pdf) — 【[note](http://www.inforsec.org/wp/?p=2049)】【[tool](https://github.com/wpengfei/double_fetch_cocci)】
13. 2017-USENIX：[DR. CHECKER- A Soundy Analysis for Linux Kernel Drivers](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-machiry.pdf) — 【[tool-dr_checker](https://github.com/ucsb-seclab/dr_checker)】
14. 2017-USENIX：[kAFL- Hardware-Assisted Feedback Fuzzing for OS Kernels](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-schumilo.pdf) — 【[note](https://www.jianshu.com/u/cd49be7bd6b5)】【[tool-kAFL](https://github.com/RUB-SysSec/kAFL)】
15. 2018-S&P：[DEADLINE-Precise and Scalable Detection of Double-Fetch Bugs in OS Kernels](http://www-users.cs.umn.edu/~kjlu/papers/deadline.pdf) — 【[note](https://www.jianshu.com/p/e4084b2c7c16)】【[note2](https://www.jianshu.com/p/7e2f15547f1e)】【[note3](https://www.inforsec.org/wp/?p=2550)】【[tool-DEADLINE](https://github.com/sslab-gatech/deadline)】
16. 2018-CCS：[Check It Again- Detecting Lacking-Recheck Bugs in OS Kernels ](https://www-users.cs.umn.edu/~kjlu/papers/lrsan.pdf)— 【[note](https://www.jianshu.com/p/2f8df6082b1d)】【[note2](https://securitygossip.com/blog/2018/11/27/check-it-again-detecting-lacking-recheck-bugs-in-os-kernels/)】【[tool-LRSan](https://github.com/kengiter/lrsan)】
17. 2018-USENIX：[MoonShine：Optimizing OS Fuzzer Seed Selection with Trace Distillation](http://www.cs.columbia.edu/~suman/docs/moonshine.pdf) — 【[note](https://www.jianshu.com/p/7e90ad222acf)】【[note2](https://blog.csdn.net/RainyD4y/article/details/106892658)】【[tool-moonshine](https://github.com/shankarapailoor/moonshine)】
18. 2018-NDSS：[K-Miner: Uncovering Memory Corruption in Linux](http://wp.internetsociety.org/ndss/wp-content/uploads/sites/25/2018/02/ndss2018_05A-1_Gens_paper.pdf) — 【[note](https://mp.weixin.qq.com/s/3N3rmAyZEbZpiBvxnjWVvA)】【[note2](https://blog.csdn.net/u012332816/article/details/79795643)】【[tool-K-Miner](https://github.com/ssl-tud/k-miner)】
19. 2019-S&P：[Razzer：Finding Kernel Race Bugs through Fuzzing](https://lifeasageek.github.io/papers/jeong-razzer.pdf) — 【[note](https://www.jianshu.com/p/43ced9660257)】【[note2](https://www.jianshu.com/p/e8296dbae313)】【[note3](https://securitygossip.com/blog/2019/03/06/razzer-finding-kernel-race-bugs-through-fuzzing/)】【[tool-razzer](https://github.com/compsec-snu/razzer)】
20. 2019-WOOT-Workshop：[Unicorefuzz- On the Viability of Emulation for Kernelspace Fuzzing](https://www.usenix.org/system/files/woot19-paper_maier.pdf) — 【[tool-unicorefuzz](https://github.com/fgsect/unicorefuzz)】
21. 2019-FSE：[Detecting Concurrency Memory Corruption Vulnerabilities](https://dl.acm.org/doi/10.1145/3338906.3338927) — 【[tool-CONVUL](https://github.com/mryancai/ConVul)】
22. 2019-S&P：[Fuzzing File Systems via Two-Dimensional Input Space Exploration](https://taesoo.kim/pubs/2019/xu:janus.pdf) — 【[note](https://www.jianshu.com/p/23c3e41254b6)】 【[note2](https://blog.csdn.net/RainyD4y/article/details/106892751)】【[tool-JANUS](https://github.com/sslab-gatech/janus)】
23. 2019-USENIX：[Detecting Missing-Check Bugs via Semantic- and Context-Aware Criticalness and Constraints Inferences](https://www.usenix.org/conference/usenixsecurity19/presentation/lu) — 【[tool-CRIX](https://github.com/umnsec/crix)】
24. 2019-USENIX-ATC：[Effective Static Analysis of Concurrency Use-After-Free Bugs in Linux Device Drivers](https://www.usenix.org/conference/atc19/presentation/bai) — 【[note](https://securitygossip.com/blog/2019/11/22/effective-static-analysis-of-concurrency-use-after-free-bugs-in-linux-device-drivers/)】
25. 2019-NDSS：[PeriScope：An Effective Probing and Fuzzing Framework for the Hardware-OS Boundary](https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04A-1_Song_paper.pdf) — 【[note](https://www.jianshu.com/p/34568906d900)】【[tool-periscope](https://github.com/securesystemslab/periscope)】
26. 2018-USENIX-ATC：[DSAC: Effective Static Analysis of Sleep-in-Atomic-Context Bugs in Kernel Modules](https://www.usenix.org/system/files/conference/atc18/atc18-bai.pdf)
27. 2020-TOCS：[Effective Detection of Sleep-in-atomic-context Bugs in the Linux Kernel](https://dl.acm.org/doi/pdf/10.1145/3381990)
28. 2020-NDSS：[HFL: Hybrid Fuzzing on the Linux Kernel](https://www.ndss-symposium.org/ndss-paper/hfl-hybrid-fuzzing-on-the-linux-kernel/) — 【[note](https://blog.csdn.net/wcventure/article/details/105281874)】【[note2](https://securitygossip.com/blog/2020/05/09/hfl-hybrid-fuzzing-on-the-linux-kernel/)】【[note3](https://mp.weixin.qq.com/s/RazaTgtrgrKfCFRKlBHyww)】
29. 2020-S&P：[Krace: Data Race Fuzzing for Kernel File Systems](https://www.computer.org/csdl/proceedings-article/sp/2020/349700b568/1iqVRYHTi24) — 【[note](https://securitygossip.com/blog/2020/06/19/krace-data-race-fuzzing-for-kernel-file-systems/)】
30. 2020-USENIX：Agamotto: Accelerating Kernel Driver Fuzzing with Lightweight Virtual Machine Checkpoints — [presentation](https://www.usenix.org/conference/usenixsecurity20/presentation/song)
31. 2020-USENIX：[Muzz: Thread-aware Grey-box Fuzzing for Effective Bug Hunting in Multithreaded Programs](https://www.usenix.org/system/files/sec20-chen-hongxu.pdf) — 【[note](https://securitygossip.com/blog/2020/09/18/muzz-thread-aware-grey-box-fuzzing-for-effective-bug-hunting-in-multithreaded-programs/)】
32. 2020-CCS：[Exaggerated Error Handling Hurts! An In-Depth Study and Context-Aware Detection](https://www-users.cs.umn.edu/~kjlu/papers/eecatch.pdf) —【[note](https://securitygossip.com/blog/2020/08/04/exaggerated-error-handling-hurts-an-in-depth-study-and-context-aware-detection/)】
33. 2020-FSE：[UBITect: A Precise and Scalable Method to Detect Use-Before-Initialization Bugs in Linux Kernel](https://www.cs.ucr.edu/~csong/fse20-ubitect.pdf) — 【[note](https://securitygossip.com/blog/2020/10/15/ubitect-a-precise-and-scalable-method-to-detect-use-before-initialization-bugs-in-linux-kernel/)】
34. 2020-LPC：[KCSAN-Data-race detection in the Linux kernel](https://www.linuxplumbersconf.org/event/7/contributions/647/attachments/549/972/LPC2020-KCSAN.pdf)
35. [2021-NDSS](https://www.ndss-symposium.org/ndss-program/ndss-2021/)：[Detecting Kernel Memory Leaks in Specialized Modules With Ownership Reasoning](https://www.ndss-symposium.org/wp-content/uploads/ndss2021_5B-4_24416_paper.pdf) — 【[note](https://securitygossip.com/blog/2021/01/12/detecting-kernel-memory-leaks-in-specialized-modules-with-ownership-reasoning/)】
36. 2021-NDSS：[KUBO: Precise and Scalable Detection of User-triggerable Undefined Behavior Bugs in OS Kernel](https://www.ndss-symposium.org/wp-content/uploads/ndss2021_1B-5_24461_paper.pdf) — 【[note](https://mp.weixin.qq.com/s/LI49ioKYMksguQMqKH1Rcw)】
37. 2021-USENIX：[Detecting Kernel Refcount Bugs with Two-Dimensional Consistency Checking](https://www.usenix.org/conference/usenixsecurity21/presentation/tan)
38. 2021-USENIX：[Understanding and Detecting Disordered Error Handling with Precise Function Pairing](https://www.usenix.org/conference/usenixsecurity21/presentation/wu-qiushi)
39. 2021-USENIX：[An Analysis of Speculative Type Confusion Vulnerabilities in the Wild](https://www.usenix.org/conference/usenixsecurity21/presentation/kirzner) 
40. 2021-USENIX：[Static Detection of Unsafe DMA Accesses in Device Drivers](https://www.usenix.org/system/files/sec21-bai.pdf) — 【[note](https://blog.csdn.net/qq_38239282/article/details/120262302)】
41. 2021-CCS：[Statically Discovering High-Order Taint Style Vulnerabilities in OS Kernels](https://www.cs.ucr.edu/~zhiyunq/pub/ccs21_static_high_order.pdf) — 【[note](https://mp.weixin.qq.com/s/Uik-cjcUHHPkRdtm22NleA)】 【[note2](https://gange666.github.io/2021/09/25/paper_notes/2021-0925-SUTURE%20a4d4fa5d0b284ee7ba496470086f0110/)】
42. 2021-CCS：[Detecting Missed Security Operations Through Differential Checking of Object-based Similar Paths](https://nesa.zju.edu.cn/download/ldh_pdf_IPPO.pdf) — 【[note](https://blog.ycdxsb.cn/e6c8cbe9.html)】
43. 2021-SOSP：[HEALER: Relation Learning Guided Kernel Fuzzing](https://dl.acm.org/doi/pdf/10.1145/3477132.3483547) — 【[tool-healer](https://github.com/SunHao-0/healer)】  【[note](https://mp.weixin.qq.com/s/SYvNC7EMf-sMeZeKMPJD0A)】 【[note2](https://www.freebuf.com/articles/292731.html)】
44. 2021-S&P：[A Novel Dynamic Analysis Infrastructure to Instrument Untrusted Execution Flow Across User-Kernel Spaces](http://www.mysmu.edu/faculty/xhding/publications/oasis-sp21.pdf)

#### （3）kernel defense

1. 2011-NDSS：[Practical Protection of Kernel Integrity for Commodity OS from Untrusted Extensions](https://www.ndss-symposium.org/ndss2011/practical-protection-of-kernel-integrity-for-commodity-os-from-untrusted-extensions) 
2. 2011-NDSS：[SigGraph - Brute Force Scanning of Kernel Data Structure Instances Using Graph-based Signatures](https://www.ndss-symposium.org/ndss2011/siggraph-brute-force-scanning-of-kernel-data-structure-instances-using-graph-based-signatures)
3. 2011-NDSS：[Efficient Monitoring of Untrusted Kernel-Mode Execution](https://www.ndss-symposium.org/ndss2011/efficient-monitoring-untrusted-kernel-mode-execution)
4. 2012-NDSS：[Kruiser - Semi-synchronized Non-blocking Concurrent Kernel Heap Buffer Overflow Monitoring](https://www.ndss-symposium.org/ndss2012/kruiser-semi-synchronized-non-blocking-concurrent-kernel-heap-buffer-overflow-monitoring)
5. 2012-OSDI：[Improving Integer Security for Systems with KINT](https://www.usenix.org/conference/osdi12/technical-sessions/presentation/wang)
6. 2012-S&P：[Smashing the Gadgets - Hindering Return-Oriented Programming Using In-place Code Randomization](https://doi.org/10.1109/SP.2012.41)
7. 2012-USS：[Enhanced Operating System Security Through Efficient and Fine-grained Address Space Randomization](https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/giuffrida)
8. 2013-EUROSYS：[Process firewalls - protecting processes during resource access](https://doi.org/10.1145/2465351.2465358)
9. 2013-NDSS：[Attack Surface Metrics and Automated Compile-Time OS Kernel Tailoring](https://www.ndss-symposium.org/ndss2013/attack-surface-metrics-and-automated-compile-time-os-kernel-tailoring)
10. 2013-S&P：[Just-In-Time Code Reuse - On the Effectiveness of Fine-Grained Address Space Layout Randomization](https://doi.org/10.1109/SP.2013.45)
11. 2014-CCS：[A Tale of Two Kernels - Towards Ending Kernel Hardening Wars with Split Kernel](https://doi.org/10.1145/2660267.2660331)
12. 2014-NDSS：[ROPecker - A Generic and Practical Approach For Defending Against ROP Attacks](https://www.ndss-symposium.org/ndss2014/ropecker-generic-and-practical-approach-defending-against-rop-attacks)
13. 2014-OSDI：[Jitk - A Trustworthy In-Kernel Interpreter Infrastructure](https://www.usenix.org/conference/osdi14/technical-sessions/presentation/wang_xi)
14. 2014-S&P：[KCoFI - Complete Control-Flow Integrity for Commodity Operating System Kernels](https://doi.org/10.1109/SP.2014.26)
15. 2014-S&P：[Dancing with Giants - Wimpy Kernels for On-Demand Isolated I/O](https://doi.org/10.1109/SP.2014.27)
16. 2015-NDSS：[Preventing Use-after-free with Dangling Pointers Nullification](https://www.ndss-symposium.org/ndss2015/preventing-use-after-free-dangling-pointers-nullification)
17. 2016-NDSS：[Enforcing Kernel Security Invariants with Data Flow Integrity](http://wp.internetsociety.org/ndss/wp-content/uploads/sites/25/2017/09/enforcing-kernal-security-invariants-data-flow-integrity.pdf)
18. 2016-OSDI：[Light-Weight Contexts - An OS Abstraction for Safety and Performance](https://www.usenix.org/conference/osdi16/technical-sessions/presentation/litton)
19. 2016-OSDI：[EbbRT - A Framework for Building Per-Application Library Operating Systems](https://www.usenix.org/conference/osdi16/technical-sessions/presentation/schatzberg)
20. 2017-EUROSYS：[A Characterization of State Spill in Modern Operating Systems](https://doi.org/10.1145/3064176.3064205)
21. 2017-EUROSYS：[kRˆX: Comprehensive Kernel Protection Against Just-In-Time Code Reuse](https://doi.org/10.1145/3064176.3064216) 【[slides](http://www.cs.columbia.edu/~theofilos/files/slides/krx.pdf)】
22. 2017-NDSS：[PT-Rand - Practical Mitigation of Data-only Attacks against Page Tables](https://www.ndss-symposium.org/ndss2017/ndss-2017-programme/pt-rand-practical-mitigation-data-only-attacks-against-page-tables/)
23. 2017-S&P：[NORAX - Enabling Execute-Only Memory for COTS Binaries on AArch64](https://doi.org/10.1109/SP.2017.30)
24. 2017-CCS：[FreeGuard - A Faster Secure Heap Allocator](https://doi.org/10.1145/3133956.3133957)
25. 2017-USENIX：[Lock-in-Pop - Securing Privileged Operating System Kernels by Keeping on the Beaten Path](https://www.usenix.org/conference/atc17/technical-sessions/presentation/li-yiwen)
26. 2017-USENIX：[Can’t Touch This: Software-only Mitigation against Rowhammer Attacks targeting Kernel Memory](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/brasser)
27. 2017-USENIX：[Oscar: A Practical Page-Permissions-Based Scheme for Thwarting Dangling Pointers](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/dang)
28. 2019-S&P：[LBM - A Security Framework for Peripherals within the Linux Kernel](https://doi.org/10.1109/SP.2019.00041)
29. 2019-S&P：[SoK - Shining Light on Shadow Stacks](https://doi.org/10.1109/SP.2019.00076)
30. 2019-S&P：[SoK - Sanitizing for Security](https://doi.org/10.1109/SP.2019.00010)
31. 2019-USENIX：[PeX: A Permission Check Analysis Framework for Linux Kernel](https://www.usenix.org/conference/usenixsecurity19/presentation/zhang-tong)
32. 2019-USENIX：[ERIM: Secure, Efficient In-process Isolation with Protection Keys (MPK)](https://www.usenix.org/conference/usenixsecurity19/presentation/vahldiek-oberwagner)
33. 2019-USENIX：[LXDs - Towards Isolation of Kernel Subsystems](https://www.usenix.org/conference/atc19/presentation/narayanan)
34. 2019-USENIX：[SafeHidden: An Efficient and Secure Information Hiding Technique Using Re-randomization](https://www.usenix.org/conference/usenixsecurity19/presentation/wang) 
35. 2020-S&P：[xMP: Selective Memory Protection for Kernel and User Space](https://www.computer.org/csdl/proceedings-article/sp/2020/349700a603/1iqVRnCoPjq)
36. 2020-S&P：[SEIMI: Efficient and Secure SMAP-Enabled Intra-process Memory Isolation](https://www.computer.org/csdl/proceedings-article/sp/2020/349700b332/1iqVRPB1xbG) — 【[note](https://securitygossip.com/blog/2020/06/12/seimi-efficient-and-secure-smap-enabled-intra-process-memory-isolation/)】
37. 2021-USENIX：[Undo Workarounds for Kernel Bugs](https://www.usenix.org/conference/usenixsecurity21/presentation/talebi)
38. 2021-USENIX：[SHARD: Fine-Grained Kernel Specialization with Context-Aware Hardening](https://www.usenix.org/conference/usenixsecurity21/presentation/abubakar)
39. 2021-USENIX：[Preventing Use-After-Free Attacks with Fast Forward Allocation](https://www.usenix.org/conference/usenixsecurity21/presentation/wickman)

other resources：

1. [security things in every version of Linux mainline](https://outflux.net/blog/)
2. [PaX code analysis](https://github.com/hardenedlinux/grsecurity-101-tutorials/tree/master/grsec-code-analysis)
3. [A Decade of Linux Kernel Vulnerabilities, their Mitigation and Open Problems-2017](https://github.com/maxking/linux-vulnerabilities-10-years)
4. [10_years_of_linux_security_by_grsecurity_2020](https://grsecurity.net/10_years_of_linux_security.pdf)—— security mechanism timeline
5. [linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)
6. [linux_mitigations](https://github.com/nccgroup/exploit_mitigations/blob/master/linux_mitigations.md)
7. [The State of Kernel Self Protection-2018](https://outflux.net/slides/2018/lca/kspp.pdf)

#### （4） Android

1. 2020-USEINX：[Automatic Hot Patch Generation for Android Kernels](https://www.usenix.org/conference/usenixsecurity20/presentation/xu)—自动给安卓打补丁 【[note](https://securitygossip.com/blog/2020/03/31/automatic-hot-patch-generation-for-android-kernels/)】



---

## 3. CVE

1. [Linux kernel 4.20 BPF 整数溢出漏洞分析](https://www.cnblogs.com/bsauce/p/11560224.html)
2. [【kernel exploit】CVE-2016-9793 错误处理负值导致访问用户空间](https://blog.csdn.net/panhewu9919/article/details/120164051)
3. [【kernel exploit】CVE-2017-5123 null任意地址写漏洞](https://bsauce.github.io/2021/05/31/CVE-2017-5123/)
4. [【CVE-2017-7184】Linux xfrm模块越界读写提权漏洞分析](https://www.cnblogs.com/bsauce/p/11634185.html)
5. [【kernel exploit】CVE-2017-6074 DCCP拥塞控制协议Double-Free提权分析](https://bsauce.github.io/2021/09/17/CVE-2017-6074/)
6. [【kernel exploit】CVE-2017-7308 AF_PACKET 环形缓冲区溢出漏洞](https://bsauce.github.io/2021/05/19/CVE-2017-7308/)
7. [【kernel exploit】CVE-2017-8890 Phoenix Talon漏洞分析与利用](https://bsauce.github.io/2021/03/22/writeup-CVE-2017-8890/)
8. [【kernel exploit】CVE-2017-11176 竞态Double-Free漏洞调试](https://bsauce.github.io/2021/02/21/CVE-2017-11176/)
9. [【CVE-2017-16995】Linux ebpf模块整数扩展问题导致提权漏洞分析](https://www.cnblogs.com/bsauce/p/11583310.html)
10. [【kernel exploit】CVE-2017-1000112 UDP报文处理不一致导致堆溢出](https://bsauce.github.io/2021/06/18/CVE-2017-1000112/)
11. [【kernel exploit】CVE-2018-5333 空指针引用漏洞](https://blog.csdn.net/panhewu9919/article/details/119153052)
12. [【kernel exploit】CVE-2019-8956 sctp_sendmsg()空指针引用漏洞](https://blog.csdn.net/panhewu9919/article/details/118557844)
13. [【kernel exploit】CVE-2019-9213 逻辑漏洞绕过 mmap_min_addr 限制](https://blog.csdn.net/panhewu9919/article/details/118557802)
14. [【kernel exploit】CVE-2019-15666 xfrm UAF 8字节写NULL提权分析](https://bsauce.github.io/2021/09/14/CVE-2019-15666/)
15. [【kernel exploit】CVE-2020-8835：eBPF verifier 错误处理导致越界读写](https://www.cnblogs.com/bsauce/p/14123111.html)
16. [【kernel exploit】BPF漏洞挖掘与CVE-2020-27194 整数溢出漏洞](https://bsauce.github.io/2020/12/14/CVE-2020-27194/)
17. [【kernel exploit】CVE-2021-3156 sudo漏洞分析与利用](https://bsauce.github.io/2021/02/01/writeup-CVE-2021-3156/)
18. [【kernel exploit】CVE-2021-26708 四字节写特殊竞争UAF转化为内核任意读写](https://bsauce.github.io/2021/04/16/writeup-CVE-2021-26708/)
19. [【kernel exploit】CVE-2021-31440 eBPF边界计算错误漏洞](https://bsauce.github.io/2021/06/09/CVE-2021-31440/)
20. [【kernel exploit】CVE-2021-3490 eBPF 32位边界计算错误漏洞](https://bsauce.github.io/2021/08/31/CVE-2021-3490/)
21. [【kernel exploit】CVE-2021-22555 2字节堆溢出写0漏洞提权分析](https://bsauce.github.io/2021/09/23/CVE-2021-22555/)



---

## 4. Tool



---

## 5. Debug & other techniques

1. [linux双机调试](https://www.cnblogs.com/bsauce/p/11634162.html)
2. [linux内核漏洞利用初探（1）：环境配置](https://blog.csdn.net/panhewu9919/article/details/99438304)
3. [【linux内核调试】SystemTap使用技巧](https://blog.csdn.net/panhewu9919/article/details/103113711)
4. [【linux内核调试】使用Ftrace来Hook linux内核函数](https://www.jianshu.com/p/bf70a262787e)
5. [【linux内核调试】ftrace/kprobes/SystemTap内核调试方法对比](https://www.jianshu.com/p/285c91c97c28)
6. [【KVM】KVM学习—实现自己的内核](https://www.jianshu.com/p/5ec4507e9be0)



---

### Reference:

[linux-security-papers](https://github.com/akshithg/linux-security-papers)

[linux-kernel-exploitation](https://github.com/xairy/linux-kernel-exploitation)

[GoSSIP_Software Security Group](https://securitygossip.com/blog/archives/)
