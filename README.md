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



## 进程调度

### 进程描述符

> 进程描述符(Process Descriptor)是操作系统内核中用于描述和管理进程的数据结构。每个活动进程都有一个对应的进程描述符，其中包含了关于该进程的各种信息

```c
/* 进程控制块数据结构 */
struct task_struct {
  /*   决定线程信息是否存在在task_struct中
    没有定义将线程信息存储在内核堆栈中
    task_struct占用变小但是查找效率小
    定义了就将线程信息定义在task_struct中
    (查找效率高,不用频繁申请释放内存,但是结构体信息增大,内存占用增加) */

  /* 当前版本定义了 */
#ifdef CONFIG_THREAD_INFO_IN_TASK
  /*
   * 由于 header soup 的原因（参见 current_thread_info()），这
   * 必须是task_struct 的第一个元素。
   */
  struct thread_info thread_info; // 存放进程运行相关信息
#endif
  unsigned int __state; // 进程状态
  // 是否启用实时补丁
#ifdef CONFIG_PREEMPT_RT
  /* saved state for "spinlock sleepers" */
  unsigned int saved_state;
#endif
    
  /* 通过该指针指向内核栈 */
  void *stack;
    
  /* 下面四个是调度策略和优先级所使用的成员 */
  int prio;             /* 进程当前的优先级 */
  int static_prio;      /* 进程的静态优先级 */
  int normal_prio;      /* 进程的正常优先级 */
  unsigned int rt_priority;  /* 实时优先级 */
    
  /* 对于普通的用户进程来说mm字段指向他的虚拟地址空间的用户空间部分，对于内核线程来说这部分为NULL */
  struct mm_struct *mm; // 指向内存描述符
  /* mm和active_mm都指向同一个内存描述符。 */
  /* 当现在是内核线程时：active_mm从别的用户进程“借用”用户空间部分(内存描述符)-->惰性TLB */
  struct mm_struct *active_mm;
    
  /* pid 用于描述用户唯一进程id  数据类型-> 整形*/
  pid_t pid;
  /* 包含父进程组 */
  pid_t tgid;
    
  /* 文件系统信息 */
  struct fs_struct *fs;

  /* 打开的文件信息 */
  struct files_struct *files;
}
```

#### thread_info

> 用于跟踪和管理线程信息

```c
struct thread_info {
  unsigned long flags;         /* 低级标志位，用于控制线程行为和状态 */
  unsigned long syscall_work;  /* 系统调用相关标志位，指示系统调用期间的工作或状态 */
  u32 status;                  /* 线程同步标志位，用于同步线程执行或表示线程状态 */
#ifdef CONFIG_SMP
  u32 cpu;                     /* 当前线程所在的处理器编号，在SMP配置下才存在 */
#endif
};
```

#### state

> 用于描述进程正在运行的状态. 他们被定义在 `include/linux/sched.h` 中
>
> 使用`ps -aux`即可查看目前正在运行的进程

**TASK_RUNNING** （运行）：进程是可执行的，就绪或者正在运行。就绪表示已经加入到运行队列中等待执行。同时，该状态也是进程在用户空间中唯一可能的状态，所以只有该状态在用户空间和内核空间都能表示。

**TASK_INTERRUPTIBLE** （可中断）：进程正在睡眠（即被阻塞），等待某些条件的达成即可被唤醒。

**TASK_UNINTERRUPTIBLE** （不可中断）：该进程即使在等待时也不受干扰，不接收信号，使用较少。

**__TASK_TRACED** **：被其他进程跟踪的进程，例如通过ptrace对调试进程进行跟踪。**

**__TASK_STTOPED** **（停止）：进程停止执行；进程没有投入运行也不能投入运行。**

```c
/* Used in tsk->__state: 进程状态*/
#define TASK_RUNNING 0x00000000         /* 进程正在运行 */
#define TASK_INTERRUPTIBLE 0x00000001   /* 可中断睡眠 */
#define TASK_UNINTERRUPTIBLE 0x00000002 /* 不可中断睡眠 */
#define __TASK_STOPPED 0x00000004       /* 进程已经停止 */
#define __TASK_TRACED 0x00000008        /* 进程正在被监视 */

/* Used in tsk->exit_state: 进程退出状态 */
#define EXIT_DEAD 0x00000010                 /* 进程已经退出 但是尚未清理 */
#define EXIT_ZOMBIE 0x00000020               /* 僵尸线程，父进程未获取到退出状态 */
#define EXIT_TRACE (EXIT_ZOMBIE | EXIT_DEAD) /* 已经退出的将是线程 */
```

#### pid_t

> pid_t 在linux内核中他是 int 整形
>
> `pid `用户进程的唯一标识
>
> `tgid` 父进程的标识

```c
// include/linux/types.h
typedef __kernel_pid_t		pid_t;

// include/uapi/asm-generic/posix_types.h
#ifndef __kernel_pid_t
// typedef 为int整形
typedef int		__kernel_pid_t;
#endif
```

### 线程的创建

> 因为写时复制技术, vfork已被抛弃.而clone可以精确地控制子进程和父进程共享哪些资源。fork函数创建的进程实际是调用了clone

```c
// 文件 kernel/fork.c

/* fork 本地直接调用clone */
#ifdef __ARCH_WANT_SYS_FORK
SYSCALL_DEFINE0(fork)
{
#ifdef CONFIG_MMU
  /* 设置参数 */
	struct kernel_clone_args args = {
		.exit_signal = SIGCHLD,
	};

  /* 直接返回clone */
	return kernel_clone(&args);
#else
	/* can not support in nommu mode */
	return -EINVAL;
#endif
}
#endif

#ifdef __ARCH_WANT_SYS_VFORK
SYSCALL_DEFINE0(vfork)
{
	struct kernel_clone_args args = {
		.flags		= CLONE_VFORK | CLONE_VM,
		.exit_signal	= SIGCHLD,
	};

	return kernel_clone(&args);
}
#endif
```

#### kernel_clone 

```c
/*
 *  Ok, this is the main fork-routine.
 *	创建新的进程
 * It copies the process, and if successful kick-starts
 * it and waits for it to finish using the VM if required.
 *
 * args->exit_signal is expected to be checked for sanity by the caller.
 */
pid_t kernel_clone(struct kernel_clone_args *args)
{
	u64 clone_flags = args->flags;  // 存储传递给函数的标志参数
	struct completion vfork;  // 定义用于vfork的完成变量
	struct pid *pid;  // 存储进程标识符（PID）的指针
	struct task_struct *p;  // 定义用于新进程的任务结构体指针
	int trace = 0;  // 用于存储是否需要跟踪的标志
	pid_t nr;  // 存储新创建进程的PID

	/*
	 * 对于传统的 clone() 调用，CLONE_PIDFD 使用 parent_tid 参数返回 pidfd。
	 * 因此，CLONE_PIDFD 和 CLONE_PARENT_SETTID 是互斥的。对于 clone3()，
	 * CLONE_PIDFD 在 struct clone_args 中增加了一个单独的字段，仍然不应该
	 * 将它们指向相同内存位置。在这里进行此检查的优势是我们不需要一个额外的
	 * 辅助函数来检查传统的 clone()。
	 */
	if ((args->flags & CLONE_PIDFD) &&
	    (args->flags & CLONE_PARENT_SETTID) &&
	    (args->pidfd == args->parent_tid))
		return -EINVAL;

	/*
	 * 确定是否以及要报告给 ptracer 的事件。
	 * 当从 kernel_thread 调用或明确请求了 CLONE_UNTRACED 时，
	 * 不报告事件；否则，如果启用了相应类型的事件，则报告。
	 */
	if (!(clone_flags & CLONE_UNTRACED)) {
		if (clone_flags & CLONE_VFORK)
			trace = PTRACE_EVENT_VFORK;
		else if (args->exit_signal != SIGCHLD)
			trace = PTRACE_EVENT_CLONE;
		else
			trace = PTRACE_EVENT_FORK;

		if (likely(!ptrace_event_enabled(current, trace)))
			trace = 0;
	}

  /* 核心复制函数, 复制进程并创建新的进程 */
	p = copy_process(NULL, trace, NUMA_NO_NODE, args);
	add_latent_entropy();

  /* 如果出现错误就返回 */
	if (IS_ERR(p))
		return PTR_ERR(p);  

	/*
	 * 在唤醒新线程之前执行此操作 -
	 * 如果线程退出得很快，线程指针可能在此时失效。
	 */
	trace_sched_process_fork(current, p);  // 跟踪新线程的调度过程

	pid = get_task_pid(p, PIDTYPE_PID);  // 获取新进程的进程标识符（PID）
	nr = pid_vnr(pid);  // 获取新进程的PID号

  /* 将新进程的PID写入 parent_tid */
	if (clone_flags & CLONE_PARENT_SETTID)
		put_user(nr, args->parent_tid); 

	if (clone_flags & CLONE_VFORK) {
		p->vfork_done = &vfork;  // 将新进程的 vfork_done 指针设置为 vfork 变量的地址
		init_completion(&vfork);  // 初始化 vfork 变量
		get_task_struct(p);  // 获取新进程的任务结构体
	}

	if (IS_ENABLED(CONFIG_LRU_GEN) && !(clone_flags & CLONE_VM)) {
		/* 锁定任务以与 memcg 迁移同步 */
		task_lock(p);
		lru_gen_add_mm(p->mm);  // 向 LRU 生成器添加地址空间
		task_unlock(p);
	}

	wake_up_new_task(p);  // 唤醒新创建的进程

	/* 进程分叉完成并开始运行，告知 ptracer */
	if (unlikely(trace))
		ptrace_event_pid(trace, pid);  // 告知 ptracer 相关事件的 PID

	if (clone_flags & CLONE_VFORK) {
		if (!wait_for_vfork_done(p, &vfork))
			ptrace_event_pid(PTRACE_EVENT_VFORK_DONE, pid);  // 如果等待 vfork 完成，则告知 ptracer VFORK_DONE 事件
	}

	put_pid(pid);  // 释放 PID 对象的引用计数
	return nr;  // 返回新创建进程的PID
}
```

###  内核调度策略优先级

```c
/*
 * 调度策略
 * 文件 tools/include/uapi/linux/sched.h
 */
#define SCHED_NORMAL		0  // 普通的时间共享进程调度策略
#define SCHED_FIFO		1  // 先进先出调度策略，也称为实时非抢占调度策略
#define SCHED_RR		2  // 轮转调度策略，也称为实时抢占调度策略
#define SCHED_BATCH		3  // 批量调度策略
/* SCHED_ISO: 保留但尚未实现 */
#define SCHED_IDLE		5  // 空闲状态调度策略
#define SCHED_DEADLINE		6  // 限期调度策略

```

#### 核心调度器

> Linux内核的核心调度器是负责管理和决定进程调度的组件。它是Linux内核中的一部分，负责决定哪个进程在何时运行，以及如何分配CPU时间给不同的进程。调度策略是决定进程调度行为的规则和算法，而Linux内核的核心调度器是实现这些调度策略的具体组件。

##### 周期性调度器

> 主调度器负责将 CPU 的使用权从一个进程切换到另一个进程。周期性调度器只是定时更新调度相关的统计信息。

void scheduler_tick(void) 函数任务

1. 更新任务的统计信息：在每个调度周期中，`scheduler_tick()`函数负责更新正在运行任务的统计数据，如运行时间、等待时间等。这些统计信息可用于进程性能分析和调度决策。
2. 检查任务调度条件：`scheduler_tick()`函数会检查是否有更高优先级的任务等待运行，或者当前任务的时间片已用尽。如果有，则需要进行任务调度，选择一个新的任务来运行。这可能涉及调用`pick_next_task()`或类似的函数来选择下一个任务。
3. 处理时间共享调度器的时间片分配：如果使用的是时间共享调度器，`scheduler_tick()`函数会处理时间片的分配。它可能会根据调度策略动态调整任务的优先级或时间片大小，以实现公平的时间共享。这样可以确保系统中的任务能够适当地分配CPU时间，避免某些任务长时间占用CPU而导致其他任务无法得到执行。

```c
/*
 * 该函数由定时器代码调用，以HZ频率。
 * 在调用时中断已被禁用。
 */
void scheduler_tick(void)
{
	int cpu = smp_processor_id();  // 获取当前CPU的ID
	struct rq *rq = cpu_rq(cpu);  // 获取当前CPU的运行队列
	struct task_struct *curr = rq->curr;  // 获取当前正在运行的任务
	struct rq_flags rf;  // 用于保护运行队列的标志
	unsigned long thermal_pressure;  // 热压力指标（thermal pressure）的值
	u64 resched_latency;  // 重新调度延迟值

	if (housekeeping_cpu(cpu, HK_TYPE_TICK))
		arch_scale_freq_tick();  // 如果是处理器维护之类的操作，则调整频率

	sched_clock_tick();  // 更新调度器时钟

	rq_lock(rq, &rf);  // 对运行队列进行锁定

	update_rq_clock(rq);  // 更新运行队列的时钟
	thermal_pressure = arch_scale_thermal_pressure(cpu_of(rq));  // 根据当前温度计算热压力
	update_thermal_load_avg(rq_clock_thermal(rq), rq, thermal_pressure);  // 更新热负载平均值
	curr->sched_class->task_tick(rq, curr, 0);  // 调用当前任务的调度类的task_tick函数进行任务调度
	if (sched_feat(LATENCY_WARN))
		resched_latency = cpu_resched_latency(rq);  // 如果启用了延迟警告，则计算重新调度延迟
	calc_global_load_tick(rq);  // 计算全局负载值
	sched_core_tick(rq);  // 执行与核心调度相关的操作
	task_tick_mm_cid(rq, curr);  // 在多处理器环境下处理内存管理相关的操作

	rq_unlock(rq, &rf);  // 解锁运行队列

	if (sched_feat(LATENCY_WARN) && resched_latency)
		resched_latency_warn(cpu, resched_latency);  // 如果启用了延迟警告且存在重新调度延迟，则发出警告

	perf_event_task_tick();  // 处理性能事件的任务计数

	if (curr->flags & PF_WQ_WORKER)
		wq_worker_tick(curr);  // 如果当前任务是工作队列的工作任务，则进行工作队列任务计数

#ifdef CONFIG_SMP
	rq->idle_balance = idle_cpu(cpu);  // 设置是否启用空闲CPU负载平衡
	trigger_load_balance(rq);  // 触发负载平衡操作
#endif
}

```

#### 完全公平调度策略

> CFS（Completely Fair Scheduler）是 Linux 内置（也是目前默认）的一个**内核调度器**， 它实现了所谓的“完全公平”调度算法，将 CPU 资源均匀地分配给各进程

CFS 实现了以下三种调度策略

```c
#define SCHED_NORMAL		0  // 普通的时间共享进程调度策略
#define SCHED_BATCH		3  // 批量调度策略
#define SCHED_IDLE		5  // 空闲状态调度策略
```

具体实现 --- 在`kernel/sched/fair.c` 中的`pick_next_task_fair`函数. 他的作用是选择下一个要运行的任务。它根据进程的优先级和运行时间等因素，在时间共享调度环境下选择下一个应该获得CPU时间的进程。因此该函数会在每个调度周期中被调用.

```c
struct task_struct *pick_next_task_fair(struct rq *rq, struct task_struct *prev, struct rq_flags *rf) {
  struct cfs_rq *cfs_rq = &rq->cfs; // 获取cfs_rq结构体指针
  struct sched_entity *se;          // 定义调度实体指针
  struct task_struct *p;            // 定义task_struct指针p
  int new_tasks;                    // 定义整型变量new_tasks

again:
  if (!sched_fair_runnable(rq)) // 如果不可运行的进程队列为空
    goto idle;                  // 跳转到idle标签

#ifdef CONFIG_FAIR_GROUP_SCHED
  if (!prev || prev->sched_class != &fair_sched_class) // 如果prev为空或者prev的调度类不是fair_sched_class
    goto simple;                                       // 跳转到simple标签

  /*
   * 因为在dequeue_task_fair()中的set_next_buddy()，
   * 很可能下一个任务属于与当前任务相同的cgroup，
   * 因此尝试避免放置和设置整个cgroup层次结构，
   * 仅更改实际改变的部分。
   */

  do {
    struct sched_entity *curr = cfs_rq->curr; // 获取当前cfs_rq的当前调度实体指针

    /*
     * 由于我们已经到这里而没有执行put_prev_entity()，
     * 我们还必须考虑cfs_rq->curr。
     * 如果它仍然是一个可运行实体，update_curr()将更新其运行时间，
     * 否则忘记我们曾经见过它。
     */
    if (curr) {
      if (curr->on_rq)
        update_curr(cfs_rq); // 更新当前cfs_rq中的任务的运行时间

      else
        curr = NULL;

      /*
       * 这次对check_cfs_rq_runtime()的调用将throttle并将其实体从父级中出队列。
       * 因此，nr_running测试将确实是正确的。
       */
      if (unlikely(check_cfs_rq_runtime(cfs_rq))) { // 检查cfs_rq的运行时间是否超过了限制

        cfs_rq = &rq->cfs; // 重置cfs_rq为rq的cfs域

        if (!cfs_rq->nr_running) // 如果cfs_rq中没有正在运行的任务
          goto idle;             // 跳转到idle标签

        goto simple; // 跳转到simple标签
      }
    }

    se = pick_next_entity(cfs_rq, curr); // 选择cfs_rq上一个调度实体的下一个调度实体
    cfs_rq = group_cfs_rq(se);           // 获取调度实体的组cfs_rq指针
  } while (cfs_rq);                      // 如果cfs_rq存在，则重复上述过程

  p = task_of(se); // 获取调度实体的task_struct指针

  /*
   * 由于我们还没有执行put_prev_entity，
   * 如果选中的任务与我们起初的任务不同，
   * 尝试接触最少数量的cfs_rq。
   */
  if (prev != p) {                        // 如果prev不等于p
    struct sched_entity *pse = &prev->se; // 获取prev的调度实体指针

    while (!(cfs_rq = is_same_group(se, pse))) {
      int se_depth = se->depth;   // 获取se的深度
      int pse_depth = pse->depth; // 获取pse的深度

      if (se_depth <= pse_depth) {
        put_prev_entity(cfs_rq_of(pse), pse); // 将pse放回cfs_rq
        pse = parent_entity(pse);             // 获取pse的父实体指针
      }
      if (se_depth >= pse_depth) {
        set_next_entity(cfs_rq_of(se), se); // 设置se为cfs_rq的下一个实体
        se = parent_entity(se);             // 获取se的父实体指针
      }
    }

    put_prev_entity(cfs_rq, pse); // 将pse放回cfs_rq
    set_next_entity(cfs_rq, se);  // 将se设置为cfs_rq的下一个实体
  }

  goto done; // 跳转到done标签

simple:
#endif

  if (prev)
    put_prev_task(rq, prev); // 在rq的prev位置放置一个任务（prev）

  do {
    se = pick_next_entity(cfs_rq, NULL); // 选择cfs_rq上的下一个实体
    set_next_entity(cfs_rq, se);         // 将se设置为cfs_rq的下一个实体
    cfs_rq = group_cfs_rq(se);           // 获取调度实体的组cfs_rq指针
  } while (cfs_rq);                      // 如果cfs_rq存在，则重复上述过程

  p = task_of(se); // 获取调度实体的task_struct指针

done:
  __maybe_unused;

#ifdef CONFIG_SMP
  /*
   * 将下一个正在运行的任务移到列表的前面，使我们的cfs_tasks列表成为MRU（most recently used）列表。
   */
  list_move(&p->se.group_node, &rq->cfs_tasks); // 将p的group_node节点移到rq的cfs_tasks列表的前面
#endif

  if (hrtick_enabled_fair(rq))
    hrtick_start_fair(rq, p); // 如果fair调度策略启用了高精度时钟，开始fair调度的高精度时钟

  update_misfit_status(p, rq);        // 更新p在rq中的错误状态
  sched_fair_update_stop_tick(rq, p); // 更新rq和p的stop_calculation_tick

  return p; // 返回选中的任务p

idle:
  if (!rf)
    return NULL; // 如果rf为空指针，返回NULL

  new_tasks = newidle_balance(rq, rf); // 在rq上进行新的负载均衡，并获取新增的任务数

  /*
   * 因为newidle_balance()释放（并重新获取）rq->lock，
   * 所以可能会出现任何具有更高优先级的任务的情况。
   * 在这种情况下，我们必须重新开始pick_next_entity()循环。
   */
  if (new_tasks < 0)
    return RETRY_TASK; // 返回RETRY_TASK标识符

  if (new_tasks > 0)
    goto again; // 跳转到again标签

  /*
   * rq即将空闲，检查是否需要更新clock_pelt的lost_idle_time。
   */
  update_idle_rq_clock_pelt(rq); // 更新空闲rq的clock_pelt的lost_idle_time

  return NULL; // 返回NULL
}
```

### 运行队列

> rq 是描述就绪队列，其设计是为每一个CPU都有一个就绪队列，本地进程在本地队列上排序

定义在 `kernel/sched/sched.h` 中

```c
/**
 * 这是主要的、每 CPU 运行队列数据结构。
 *
 * 锁定规则：那些想要锁定多个runqueue的地方
 *（比如负载均衡或者线程迁移的代码），锁
 * 获取操作必须按升序 &runqueue 排序。
 */
struct rq {
  /* runqueue lock: */
  raw_spinlock_t		__lock;  // 运行队列的自旋锁
  unsigned int		nr_running;  // 当前运行的任务数目
  // ...

#ifdef CONFIG_SMP
  unsigned int		nr_pinned;  // 固定在该CPU上的任务数目
#endif
  unsigned int		push_busy;  // 繁忙推送计数
  struct cpu_stop_work	push_work;  // 繁忙推送工作

#ifdef CONFIG_SCHED_CORE
  /* per rq */
  struct rq		*core;  // 指向共享核心的rq指针
  struct task_struct	*core_pick;  // 指向在共享核心上选择中的任务
  unsigned int		core_enabled;  // 共享核心是否启用
  unsigned int		core_sched_seq;  // 共享核心的调度顺序
  struct rb_root		core_tree;  // 共享核心的红黑树

  /* shared state -- careful with sched_core_cpu_deactivate() */
  unsigned int		core_task_seq;  // 共享核心任务的顺序
  unsigned int		core_pick_seq;  // 共享核心选择任务的顺序
  unsigned long		core_cookie;  // 共享核心的cookie值
  unsigned int		core_forceidle_count;  // 共享核心的强制空闲计数
  unsigned int		core_forceidle_seq;  // 共享核心的强制空闲调度序列
  unsigned int		core_forceidle_occupation;  // 共享核心的强制空闲占用情况
  u64			core_forceidle_start;  // 共享核心的强制空闲的开始时间
#endif
  // .....
};

```

### 调度进程

> `schedule()`函数是任务调度器的核心部分，负责选择下一个要运行的任务并进行上下文切换. 
>
> 他在文件 `kernel/sched/core.c` 中被定义

```c
/* 调度器关键函数 */
asmlinkage __visible void __sched schedule(void) {
  struct task_struct *tsk = current; // 获取当前正在运行的任务的结构体指针 tsk
  sched_submit_work(tsk); // 提交当前任务给调度器进行处理
  // 进入循环，直到不再需要进行任务调度
  do {
    preempt_disable(); // 禁用内核抢占，确保在调度过程中不会被其他任务抢占
    /* 主要委托函数,大部分工作由他完成 */
    __schedule(SM_NONE); // 选择下一个要运行的任务并进行上下文切换
    sched_preempt_enable_no_resched(); // 启用内核抢占，允许其他任务抢占当前任务的执行，但不触发重新调度
  } while (need_resched()); // 检查是否需要进行任务调度
  sched_update_worker(tsk); // 更新当前任务的状态
}
```

#### __schedule

> 主要实现: `pick_next_task` 选择下一个进程, `context_switch` 切换进程

```

  /* 选择下一个进程 */
  next = pick_next_task(rq, prev, &rf);


  /* Also unlocks the rq: */
  /* 切换进程 */
  rq = context_switch(rq, prev, next, &rf);
```

#### pick_next_task

> `pick_next_task` 最后调用`__pick_next_task`来进程下一个进程的选择.

```c
/*
 * 选取优先级最高的任务:
 */
static inline struct task_struct *
__pick_next_task(struct rq *rq, struct task_struct *prev, struct rq_flags *rf)
{
	const struct sched_class *class;
	struct task_struct *p;

	/*
	 * 优化：我们知道，如果所有任务都在公平类别中，我们可以
	 * 直接调用该函数，但前提是 @prev 任务不是
	 * 更高的调度等级，因为否则那些会失去
	 * 有机会从其他 CPU 中获取更多工作。
	 */
	if (likely(!sched_class_above(prev->sched_class, &fair_sched_class) &&
		   rq->nr_running == rq->cfs.h_nr_running)) {

		// 选择下一个公平类 (fair class) 的任务
		p = pick_next_task_fair(rq, prev, rf);
		if (unlikely(p == RETRY_TASK))
			goto restart;

		/* Assume the next prioritized class is idle_sched_class */
		// 如果没有找到任务，则切换到 idle 类 (idle_sched_class) 并选择任务
		if (!p) {
			put_prev_task(rq, prev);
			p = pick_next_task_idle(rq);
		}

		return p;
	}

restart:
	// 清理之前的任务选择状态
	put_prev_task_balance(rq, prev, rf);

	// 遍历每个调度类 (sched_class)
	for_each_class(class) {
		// 选择下一个任务
		p = class->pick_next_task(rq);
		if (p)
			return p;
	}

	// 如果代码执行到此处，表示出现了错误，因为 idle 类 (idle_sched_class) 应该始终有可运行的任务
	BUG(); /* The idle class should always have a runnable task. */
}
```



## 参考文章

1. https://zhuanlan.zhihu.com/p/618611333
   1. 在子进程中，成功的fork()返回0；在父进程中，fork()会返回子进程的pid
2. https://zhuanlan.zhihu.com/p/583705942
   1. 进程的虚拟地址空间分为用户虚拟地址空间3G和内核虚拟地址空间1G。所有进程`共享内核虚拟地址空间`，每个进程有`独立的用户空间虚拟地址空间`
   2. 没有用户虚拟地址空间的进程称为内核线程，共享用户虚拟地址空间的进程称为用户线程
   3. 在 Linux 内核中，新进程是从一个已经存在的进程复制出来的，内核使用静态数据结构造出 0 号内核线程，
3. https://arthurchiao.art/blog/linux-cfs-design-and-implementation-zh/#11-cfs%E8%BF%9B%E7%A8%8Btask%E7%9A%84%E5%85%AC%E5%B9%B3%E8%B0%83%E5%BA%A6
   1. CFS（Completely Fair Scheduler）是 Linux 内置（也是目前默认）的一个**内核调度器**， 如名字所示，它实现了所谓的“完全公平”调度算法，将 CPU 资源均匀地分配给各进程
4. 是否

