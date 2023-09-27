# Linux 内核学习

> 主力学习进程调度方向

## 快速入门

### 安装

```bash
git clone --depth 1 https://github.com/torvalds/linux.git # 直接克隆地址

# fork自己仓库然后克隆
```

### 目录结构

1. **arch**：存储特定体系结构的架构相关代码，例如x86、ARM、MIPS等。
2. **block**：包含块设备相关的代码，例如硬盘、SSD等块设备的驱动。
3. **certs**：存储内核代码签名和认证相关的证书和密钥。
4. **crypto**：包含加密算法和密码学库相关的代码，用于提供安全性和加密功能。
5. **Documentation**：存储内核文档，包括开发者文档、配置选项说明、子系统概述等。
6. **drivers**：包含设备驱动程序，用于支持各种硬件设备，如显卡、网卡、声卡等。
7. **fs**：**VFS 子系统**：虚拟文件系统（Virtual File System，简称 VFS）的代码，用于统一管理各种文件系统和文件操作。
8. **include**：存储头文件，包含内核代码中需要包含的C语言头文件。
9. **init**：包含内核初始化和启动代码，这是内核启动时的入口点。
10. **ipc**：存储进程间通信（IPC）相关的代码，如消息队列、信号量等。
11. **kernel**：包含内核的核心代码，涵盖进程管理、内存管理、调度等核心操作系统功能。
12. **lib**：存储内核中通用的实用程序和库函数，用于各个子系统。
13. **LICENSES**：包含内核中使用的各种开源许可证的文本文件。
14. **mm**：存储内存管理相关的代码，包括页表管理、内存分配、交换等。
15. **net**：存储网络协议栈和网络设备驱动程序相关的代码。
16. **samples**：包含示例代码和演示如何使用内核API的示例程序。
17. **scripts**：存储用于内核构建、配置和维护的脚本。
18. **security**：包含安全子系统相关的代码，如SELinux、AppArmor等。
19. **sound**：存储声音子系统相关的代码，用于支持音频设备。
20. **tools**：包含用于内核开发的实用工具和脚本。
21. **usr**：包含用户空间工具，用于与内核进行交互。
22. **CREDITS**：包含对内核贡献者的感谢列表。
23. **Kbuild**：包含内核构建系统的配置文件和规则。
24. **Kconfig**：包含内核配置选项的定义，用于配置编译选项。
25. **Makefile**：包含内核的顶层Makefile，用于构建内核。
26. **COPYING**：包含Linux内核的版权声明和使用条款。
27. **MAINTAINERS**：包含内核子系统的维护者列表和联系信息。