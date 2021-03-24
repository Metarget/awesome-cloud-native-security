# Awesome Cloud Native Security

![](images/banner.png)

This repository is used to collect **AWESOME** resources on the topic of cloud native security found during research.

Hope to be helpful :)

## 1 Offensive

### 1.1 General

- [2018 绿盟科技容器安全技术报告](https://www.nsfocus.com.cn/upload/contents/2018/11/20181109100414_79051.pdf)
- [2020 绿盟科技云原生安全技术报告](http://blog.nsfocus.net/wp-content/uploads/2021/01/Technical-Report-of-Cloud-Native-Security.pdf)
- [国内首个云上容器ATT&CK攻防矩阵发布，阿里云助力企业容器化安全落地](https://developer.aliyun.com/article/765449)
- [MITRE ATT&CK framework for container runtime security with Falco.](https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/)
- [Threat matrix for Kubernetes (Microsoft)](https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/)
- [云原生环境渗透工具考察](https://wohin.me/yun-yuan-sheng-huan-jing-shen-tou-xiang-guan-gong-ju-kao-cha/)
- [红蓝对抗中的云原生漏洞挖掘及利用实录](https://mp.weixin.qq.com/s/Aq8RrH34PTkmF8lKzdY38g)

### 1.2 Kubernetes

- [Walls Within Walls: What if your attacker knows parkour? (KubeCon 2019)](https://kccncna19.sched.com/event/UaeM/walls-within-walls-what-if-your-attacker-knows-parkour-tim-allclair-greg-castle-google)
    - [Walls Within Walls: What if Your Attacker Knows Parkour? (Video)](https://www.youtube.com/watch?v=6rMGRvcjvKc)
- [k0otkit：针对K8s集群的通用后渗透控制技术 (CIS 2020)](https://github.com/brant-ruan/k0otkit/blob/main/CIS2020-slide.pdf)
    - [k0otkit: Hack K8s in a K8s Way](https://wohin.me/k0otkit-hack-k8s-in-a-k8s-way/)
- [Advanced Persistence Threats: The Future of Kubernetes Attacks (RSA 2020)](https://published-prd.lanyonevents.com/published/rsaus20/sessionsFiles/18317/2020_USA20_CSV-F01_01_Advanced%20Persistence%20Threats%20The%20Future%20of%20Kubernetes%20Attacks.pdf)
- [Command and KubeCTL: Real-world Kubernetes Security for Pentesters (Shmoocon 2020)](https://docs.google.com/presentation/d/1y6KGGT5Uw27cCgFMKiGv0NjRhq8YvjY_S9UG8s_TThg/edit#slide=id.g6d20dd40e5_0_1816)
    - [Deep Dive into Real-World Kubernetes Threats](https://research.nccgroup.com/2020/02/12/command-and-kubectl-talk-follow-up/)

### 1.3 Container

#### 1.3.1 General

- [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)
- [Well, That Escalated Quickly! How Abusing Docker API Led to Remote Code Execution, Same Origin Bypass and Persistence in The Hypervisor via Shadow Containers (Black Hat 2017)](https://www.blackhat.com/docs/us-17/thursday/us-17-Cherny-Well-That-Escalated-Quickly-How-Abusing-The-Docker-API-Led-To-Remote-Code-Execution-Same-Origin-Bypass-And-Persistence.pdf)
- [里应外合：借容器root提权](https://wohin.me/li-ying-wai-he-jie-zhu-rong-qi-root/)
- [针对容器的渗透测试方法](https://mp.weixin.qq.com/s?subscene=19&__biz=MzIyODYzNTU2OA==&mid=2247487590&idx=1&sn=060a8bdf2ddfaff6ceae5cb931cb27ab&chksm=e84fb6b9df383faf1723040a0d6f0300c9517db902ef0010e230d8e802b1dfe9d8b95e6aabbd)
- [A Methodology for Penetration Testing Docker Systems](https://www.cs.ru.nl/bachelors-theses/2020/Joren_Vrancken___4593847___A_Methodology_for_Penetration_Testing_Docker_Systems.pdf)
- [CVE-2021-21287: 容器与云的碰撞——一次对MinIO的测试](https://www.leavesongs.com/PENETRATION/the-collision-of-containers-and-the-cloud-pentesting-a-MinIO.html)
- [Houdini’s Escape: Breaking the Resource Rein of Linux Control Groups](http://www.cs.memphis.edu/~xgao1/paper/ccs19.pdf)

#### 1.3.2 Container Escape

- [A Compendium of Container Escapes (Black Hat 2019)](https://capsule8.com/assets/ug/us-19-Edwards-Compendium-Of-Container-Escapes.pdf)
- [Escaping Virtualized Containers (Black Hat 2020)](https://i.blackhat.com/USA-20/Thursday/us-20-Avrahami-Escaping-Virtualized-Containers.pdf)
    - [Kata Containers逃逸研究](https://mp.weixin.qq.com/s/q4xJtlO6iFpHQginGvVBDQ)
- [In-and-out - Security of Copying to and from Live Containers (Open Source Summit 2019)](https://osseu19.sched.com/event/TLC4/in-and-out-security-of-copying-to-and-from-live-containers-ariel-zelivansky-yuval-avrahami-twistlock)
- [容器逃逸技术概览](https://wohin.me/rong-qi-tao-yi-gong-fang-xi-lie-yi-tao-yi-ji-zhu-gai-lan/)
- [容器逃逸成真：从CTF到CVE-2019-5736](https://wohin.me/rong-qi-tao-yi-cheng-zhen-cong-ctfjie-ti-dao-cve-2019-5736lou-dong-wa-jue-fen-xi/)
- [Github: awesome-container-escape](https://github.com/brant-ruan/awesome-container-escape)
- [ABSTRACT SHIMMER (CVE-2020-15257): Host Networking is root-Equivalent, Again](https://research.nccgroup.com/2020/12/10/abstract-shimmer-cve-2020-15257-host-networking-is-root-equivalent-again/)

### 1.4 Others

- [腾讯蓝军安全提醒：开源云原生API网关 Kong 可能会成为攻击方进入企业内网的新入口](https://security.tencent.com/index.php/announcement/msg/193)
- [Istio访问授权再曝高危漏洞 (CVE-2020-8595)](https://mp.weixin.qq.com/s/IHJAsO2SktNXqQGNLuTYUQ)

### 1.5 Tools

- [kube-hunter](https://github.com/aquasecurity/kube-hunter)
- [k0otkit - Manipulate K8s in a K8s way](https://github.com/brant-ruan/k0otkit)
- [CDK - Zero Dependency Container Penetration Toolkit](https://github.com/cdk-team/CDK)

## 2 Defensive

### 2.1 Container

- [NIST.SP.800-190 Application Container Security Guide](https://csrc.nist.gov/publications/detail/sp/800-190/final)
- [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc_group_understanding_hardening_linux_containers-1-1.pdf)
- [容器环境相关的内核漏洞缓解技术](https://mp.weixin.qq.com/s?__biz=MzIyODYzNTU2OA==&mid=2247488536&idx=1&sn=fd2fcb732e76b2243f972f7a79be2b19)
- [云原生之容器安全实践](https://tech.meituan.com/2020/03/12/cloud-native-security.html)
- [探索Sysdig Falco：容器环境下的异常行为检测工具](https://wohin.me/tan-suo-sysdig-falco-rong-qi-huan-jing-xia-de-yi-chang-xing-wei-jian-ce-gong-ju/)
- [国外顶尖容器安全产品是怎么做的](https://mp.weixin.qq.com/s/JypEOt3N0li9l1KToToHZA)

### 2.2 Network

- [BASTION: A Security Enforcement Network Stack for Container Networks](https://www.usenix.org/system/files/atc20-nam.pdf)