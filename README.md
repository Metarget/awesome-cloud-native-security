# Awesome Cloud Native Security

![](images/banner.png)

This repository is used to collect **AWESOME** resources on the topic of cloud native security found during research.

Hope to be helpful :)

## 0 General

- [Hacking and Hardening Kubernetes Clusters by Example (KubeCon 2017)](https://github.com/sbueringer/kubecon-slides/blob/master/slides/2017-kubecon-na/Hacking%20and%20Hardening%20Kubernetes%20Clusters%20by%20Example%20%5BI%5D%20-%20Brad%20Geesaman%2C%20Symantec%20-%20Hacking%20and%20Hardening%20Kubernetes%20By%20Example%20v2.pdf)
- [2018绿盟科技容器安全技术报告 (2018-11)](https://www.nsfocus.com.cn/upload/contents/2018/11/20181109100414_79051.pdf)
    - [2020绿盟科技云原生安全技术报告 (2021-01)](http://blog.nsfocus.net/wp-content/uploads/2021/01/Technical-Report-of-Cloud-Native-Security.pdf)
- [A Measurement Study on Linux Container Security: Attacks and Countermeasures (ACSAC 2018)](https://csis.gmu.edu/ksun/publications/container-acsac18.pdf)
- [Kubernetes Security: Operating Kubernetes Clusters and Applications Safely (Book, 2018-09-28)](https://book4you.org/book/11026038/453528)
    - [Container Security: Fundamental Technology Concepts that Protect Containerized Applications (Book, 2020-04-01)](https://sg1lib.org/book/5534739/4f0c10)
- [MITRE ATT&CK framework for container runtime security with Falco. (2019-05-10)](https://sysdig.com/blog/mitre-attck-framework-for-container-runtime-security-with-sysdig-falco/)
- [Containers' Security: Issues, Challenges, and Road Ahead (IEEE Access 2019)](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=8693491)
- [Threat matrix for Kubernetes (Microsoft, 2020-04-02)](https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/)
    - [Secure containerized environments with updated threat matrix for Kubernetes (2021-03-23)](https://www.microsoft.com/security/blog/2021/03/23/secure-containerized-environments-with-updated-threat-matrix-for-kubernetes/)
- [国内首个云上容器ATT&CK攻防矩阵发布，阿里云助力企业容器化安全落地 (2020-06-18)](https://developer.aliyun.com/article/765449)
- [Sysdig 2021 Container Security and Usage Report (2021-01-01)](https://sysdig.com/wp-content/uploads/2021-container-security-and-usage-report.pdf)

## 1 Offensive

### 1.1 General

- [云原生环境渗透工具考察 (2020-06-22)](https://wohin.me/yun-yuan-sheng-huan-jing-shen-tou-xiang-guan-gong-ju-kao-cha/)
- [红蓝对抗中的云原生漏洞挖掘及利用实录 (2021-03-02)](https://mp.weixin.qq.com/s/Aq8RrH34PTkmF8lKzdY38g)

### 1.2 Kubernetes

#### 1.2.1 General

- [Walls Within Walls: What if your attacker knows parkour? (KubeCon 2019)](https://kccncna19.sched.com/event/UaeM/walls-within-walls-what-if-your-attacker-knows-parkour-tim-allclair-greg-castle-google)
    - [Walls Within Walls: What if Your Attacker Knows Parkour? (Video)](https://www.youtube.com/watch?v=6rMGRvcjvKc)
- [k0otkit：针对K8s集群的通用后渗透控制技术 (CIS 2020)](https://github.com/brant-ruan/k0otkit/blob/main/CIS2020-slide.pdf)
    - [k0otkit: Hack K8s in a K8s Way (Paper)](https://wohin.me/k0otkit-hack-k8s-in-a-k8s-way/)
    - [k0otkit: Hack K8s in a K8s Way (Video)](https://cis.freebuf.com/?id=65)
- [Advanced Persistence Threats: The Future of Kubernetes Attacks (RSA 2020)](https://published-prd.lanyonevents.com/published/rsaus20/sessionsFiles/18317/2020_USA20_CSV-F01_01_Advanced%20Persistence%20Threats%20The%20Future%20of%20Kubernetes%20Attacks.pdf)
    - [Advanced Persistence Threats: The Future of Kubernetes Attacks (Video)](https://www.youtube.com/watch?v=CH7S5rE3j8w)
- [Compromising Kubernetes Cluster by Exploiting RBAC Permissions (RSA 2020)](https://published-prd.lanyonevents.com/published/rsaus20/sessionsFiles/18100/2020_USA20_DSO-W01_01_Compromising%20Kubernetes%20Cluster%20by%20Exploiting%20RBAC%20Permissions.pdf)
    - [Compromising Kubernetes Cluster by Exploiting RBAC Permissions (Video)](https://www.youtube.com/watch?v=1LMo0CftVC4)
- [Command and KubeCTL: Real-world Kubernetes Security for Pentesters (Shmoocon 2020)](https://docs.google.com/presentation/d/1y6KGGT5Uw27cCgFMKiGv0NjRhq8YvjY_S9UG8s_TThg/edit#slide=id.g6d20dd40e5_0_1816)
    - [Deep Dive into Real-World Kubernetes Threats (2020-02-12)](https://research.nccgroup.com/2020/02/12/command-and-kubectl-talk-follow-up/)

#### 1.2.2 Vulnerabilities and Exploits

- [Understanding about CVE-2017–1002101 on kubernetes (2018-03-19)](https://makocchi.medium.com/kubernetes-cve-2017-1002101-en-5a30bf701a3e)
    - [Fixing the Subpath Volume Vulnerability in Kubernetes (2018-04-04)](https://kubernetes.io/blog/2018/04/04/fixing-subpath-volume-vulnerability/)
- [The Story of the First Kubernetes Critical CVE (CVE-2018-1002105, 2018-12-04)](https://rancher.com/blog/2018/2018-12-04-k8s-cve/)
    - [CVE-2018-1002105（k8s特权提升）原理与利用分析报告 (2018-12-08)](https://xz.aliyun.com/t/3542)
- [Kubernetes Vulnerability Puts Clusters at Risk of Takeover (CVE-2020-8558) (2020-07-27)](https://unit42.paloaltonetworks.com/cve-2020-8558/)

### 1.3 Container

#### 1.3.1 General

- [Abusing Privileged and Unprivileged Linux Containers (2016-06-01)](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)
- [Well, That Escalated Quickly! How Abusing Docker API Led to Remote Code Execution, Same Origin Bypass and Persistence in The Hypervisor via Shadow Containers (Black Hat 2017)](https://www.blackhat.com/docs/us-17/thursday/us-17-Cherny-Well-That-Escalated-Quickly-How-Abusing-The-Docker-API-Led-To-Remote-Code-Execution-Same-Origin-Bypass-And-Persistence.pdf)
- [Houdini’s Escape: Breaking the Resource Rein of Linux Control Groups (CCS 2019)](http://www.cs.memphis.edu/~xgao1/paper/ccs19.pdf)
    - [Houdini’s Escape: Breaking the Resource Rein of Linux Control Groups (Video)](https://www.youtube.com/watch?v=PPo9sQnJaec)
- [A Methodology for Penetration Testing Docker Systems (Bachelor Theses, 2020-01-17)](https://www.cs.ru.nl/bachelors-theses/2020/Joren_Vrancken___4593847___A_Methodology_for_Penetration_Testing_Docker_Systems.pdf)
    - [针对容器的渗透测试方法 (2020-04-17)](https://mp.weixin.qq.com/s?subscene=19&__biz=MzIyODYzNTU2OA==&mid=2247487590&idx=1&sn=060a8bdf2ddfaff6ceae5cb931cb27ab&chksm=e84fb6b9df383faf1723040a0d6f0300c9517db902ef0010e230d8e802b1dfe9d8b95e6aabbd)
- [里应外合：借容器root提权 (2020-12-03)](https://wohin.me/li-ying-wai-he-jie-zhu-rong-qi-root/)
- [CVE-2021-21287: 容器与云的碰撞——一次对MinIO的测试 (2021-01-30)](https://www.leavesongs.com/PENETRATION/the-collision-of-containers-and-the-cloud-pentesting-a-MinIO.html)

#### 1.3.2 Container Escape

- [Dirty COW - (CVE-2016-5195) - Docker Container Escape (2017-09)](https://blog.paranoidsoftware.com/dirty-cow-cve-2016-5195-docker-container-escape/)
- [A Compendium of Container Escapes (Black Hat 2019)](https://capsule8.com/assets/ug/us-19-Edwards-Compendium-Of-Container-Escapes.pdf)
- [In-and-out - Security of Copying to and from Live Containers (Open Source Summit 2019)](https://osseu19.sched.com/event/TLC4/in-and-out-security-of-copying-to-and-from-live-containers-ariel-zelivansky-yuval-avrahami-twistlock)
- [CVE-2019-5736: Escape from Docker and Kubernetes containers to root on host (2019-02-13)](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)
    - [Escaping a Broken Container - 'namespaces' from 35C3 CTF (2019-04-15)](http://blog.perfect.blue/namespaces-35c3ctf)
    - [容器逃逸成真：从CTF到CVE-2019-5736 (2019-11-20)](https://wohin.me/rong-qi-tao-yi-cheng-zhen-cong-ctfjie-ti-dao-cve-2019-5736lou-dong-wa-jue-fen-xi/)
- [容器逃逸技术概览 (2020-02-21)](https://wohin.me/rong-qi-tao-yi-gong-fang-xi-lie-yi-tao-yi-ji-zhu-gai-lan/)
- [Escaping Virtualized Containers (Black Hat 2020)](https://i.blackhat.com/USA-20/Thursday/us-20-Avrahami-Escaping-Virtualized-Containers.pdf)
    - [Kata Containers逃逸研究 (2020-09-25)](https://mp.weixin.qq.com/s/q4xJtlO6iFpHQginGvVBDQ)
- [host模式容器逃逸漏洞（CVE-2020-15257）技术分析 (2020-12-02)](https://mp.weixin.qq.com/s/WmSaLPnG4o4Co1xRiYCOnQ)
    - [ABSTRACT SHIMMER (CVE-2020-15257): Host Networking is root-Equivalent, Again (2020-12-10)](https://research.nccgroup.com/2020/12/10/abstract-shimmer-cve-2020-15257-host-networking-is-root-equivalent-again/)
    - [容器逃逸CVE-2020-15257 containerd-shim Exploit开发 (2020-12-14)](https://www.cdxy.me/?p=837)
- [How We Escaped Docker in Azure Functions (2021-01-27)](https://www.intezer.com/blog/research/how-we-escaped-docker-in-azure-functions/)

### 1.4 Serverless

- [Hacking Serverless Runtimes (Black Hat 2017)](https://www.blackhat.com/docs/us-17/wednesday/us-17-Krug-Hacking-Severless-Runtimes.pdf)
    - [Hacking Serverless Runtimes (Whitepaper)](https://www.blackhat.com/docs/us-17/wednesday/us-17-Krug-Hacking-Severless-Runtimes-wp.pdf)
- [Serverless Toolkit for Pentesters (2018-11-11)](https://blog.ropnop.com/serverless-toolkit-for-pentesters/)
- [Serverless Red Team Infrastructure: Part 1, Web Bugs (2018-09)](https://www.mdsec.co.uk/2018/09/serverless-red-team-infrastructure-part-1-web-bugs/)
- [针对AWS Lambda的运行时攻击 (2020-12-02)](https://mp.weixin.qq.com/s?__biz=MzIyODYzNTU2OA==&mid=2247488901&idx=1&sn=4d7bdb1ddf015cb77ea4e8bc0978712f&chksm=e84fb35adf383a4ca9e9b7cb0dce91cf757e043d74201361537aa6cd0e80cf6afaf1c63eb1e5&mpshare=1&scene=1&srcid=0331LaY4vmtzqLyDuZ41Y8GB&sharer_sharetime=1617201942068&sharer_shareid=353a216cfe47b39b5c642fc1dbddb3ef&version=3.1.0.2353&platform=mac#rd)

### 1.6 Service Mesh

- [A Survey of Istio’s Network Security Features (2020-03-04)](https://research.nccgroup.com/2020/03/04/a-survey-of-istios-network-security-features/)
- [Istio访问授权再曝高危漏洞 (CVE-2020-8595, 2020-03-13)](https://mp.weixin.qq.com/s/IHJAsO2SktNXqQGNLuTYUQ)

### 1.7 API Gateway

- [腾讯蓝军安全提醒：开源云原生API网关Kong可能会成为攻击方进入企业内网的新入口(CVE-2020-11710) (2020-04-15)](https://security.tencent.com/index.php/announcement/msg/193)

### 1.8 Tools

- [kube-hunter](https://github.com/aquasecurity/kube-hunter)
- [serverless_toolkit](https://github.com/ropnop/serverless_toolkit)
- [k0otkit - Manipulate K8s in a K8s way](https://github.com/brant-ruan/k0otkit)
- [CDK - Zero Dependency Container Penetration Toolkit](https://github.com/cdk-team/CDK)

## 2 Defensive

### 2.1 Standards and Benchmarks

- [NIST.SP.800-190 Application Container Security Guide (2017-09-25)](https://csrc.nist.gov/publications/detail/sp/800-190/final)
- [NIST.IR.8176 Security Assurance Requirements for Linux Application Container Deployments (2017-10)](https://nvlpubs.nist.gov/nistpubs/ir/2017/NIST.IR.8176.pdf)
- [OWASP Container Security Verification Standard](https://github.com/OWASP/Container-Security-Verification-Standard)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker/)

### 2.2 Container

- [Understanding and Hardening Linux Containers (2016-06-29)](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc_group_understanding_hardening_linux_containers-1-1.pdf)
- [探索Sysdig Falco：容器环境下的异常行为检测工具 (2019-09-25)](https://wohin.me/tan-suo-sysdig-falco-rong-qi-huan-jing-xia-de-yi-chang-xing-wei-jian-ce-gong-ju/)
- [云原生之容器安全实践 (2020-03-12)](https://tech.meituan.com/2020/03/12/cloud-native-security.html)
- [容器环境相关的内核漏洞缓解技术 (2020-08-31)](https://mp.weixin.qq.com/s?__biz=MzIyODYzNTU2OA==&mid=2247488536&idx=1&sn=fd2fcb732e76b2243f972f7a79be2b19)

### 2.3 Secure Container

- [Making Containers More Isolated: An Overview of Sandboxed Container Technologies (2019-06-06)](https://unit42.paloaltonetworks.com/making-containers-more-isolated-an-overview-of-sandboxed-container-technologies/)
- [深度解析 AWS Firecracker 原理篇 – 虚拟化与容器运行时技术 (2019-12-09)](https://aws.amazon.com/cn/blogs/china/deep-analysis-aws-firecracker-principle-virtualization-container-runtime-technology/)
- [以Docker为代表的传统容器到了生死存亡之际 (2019-12-24)](https://mp.weixin.qq.com/s/3OkDCNdwumIP9qj_FS_Kzg)
- [Kata Containers创始人：安全容器导论 (2019-12-26)](https://mp.weixin.qq.com/s?__biz=MzI0Nzc3MTQyMw==&mid=2247490237&idx=1&sn=eebe19ed1f693400cbad9b6e91b5dfb4&chksm=e9aba2cddedc2bdbae69c61f49b014f95052f377daa65f7522dbae92fe5fde62edecd70a7eca&token=347966226&lang=zh_CN#rd)

### 2.4 Network

- [BASTION: A Security Enforcement Network Stack for Container Networks (USENIX 2020)](https://www.usenix.org/system/files/atc20-nam.pdf)

### 2.5 Practices

- [国外顶尖容器安全产品是怎么做的 (2020-12-04)](https://mp.weixin.qq.com/s/JypEOt3N0li9l1KToToHZA)
- [Detecting MITRE ATT&CK: Defense evasion techniques with Falco (2021-02-02)](https://sysdig.com/blog/mitre-defense-evasion-falco/)
- [Detecting MITRE ATT&CK: Privilege escalation with Falco (2021-03-02)](https://sysdig.com/blog/mitre-privilege-escalation-falco/)

### 2.6 Tools

- [docker-bench-security](https://github.com/docker/docker-bench-security)
- [Falco](https://github.com/falcosecurity/falco)

## 3 Incidents

- [Lessons from the Cryptojacking Attack at Tesla (2018-02-20)](https://web.archive.org/web/20180222103919/https://blog.redlock.io/cryptojacking-tesla)
- [Graboid: First-Ever Cryptojacking Worm Found in Images on Docker Hub (2019-10-15)](https://unit42.paloaltonetworks.com/graboid-first-ever-cryptojacking-worm-found-in-images-on-docker-hub/)
- [Detect large-scale cryptocurrency mining attack against Kubernetes clusters (2020-04-08)](https://azure.microsoft.com/en-us/blog/detect-largescale-cryptocurrency-mining-attack-against-kubernetes-clusters/)
- [Misconfigured Kubeflow workloads are a security risk (2020-06-10)](https://www.microsoft.com/security/blog/2020/06/10/misconfigured-kubeflow-workloads-are-a-security-risk/)
- [Hildegard: New TeamTNT Cryptojacking Malware Targeting Kubernetes (2021-02-03)](https://unit42.paloaltonetworks.com/hildegard-malware-teamtnt/)