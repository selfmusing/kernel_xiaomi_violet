/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/sched.h>
#include <linux/sched/autogroup.h>
#include <linux/sched/sysctl.h>
#include <linux/sched/topology.h>
#include <linux/sched/rt.h>
#include <linux/sched/deadline.h>
#include <linux/sched/clock.h>
#include <linux/sched/wake_q.h>
#include <linux/sched/signal.h>
#include <linux/sched/numa_balancing.h>
#include <linux/sched/mm.h>
#include <linux/sched/cpufreq.h>
#include <linux/sched/stat.h>
#include <linux/sched/nohz.h>
#include <linux/sched/debug.h>
#include <linux/sched/hotplug.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/sched/cputime.h>
#include <linux/sched/init.h>
#include <linux/sched/smt.h>

#include <linux/u64_stats_sync.h>
#include <linux/kernel_stat.h>
#include <linux/binfmts.h>
#include <linux/mutex.h>
#include <linux/psi.h>
#include <linux/spinlock.h>
#include <linux/stop_machine.h>
#include <linux/irq_work.h>
#include <linux/tick.h>
#include <linux/slab.h>

#ifdef CONFIG_PARAVIRT
#include <asm/paravirt.h>
#endif

#include "cpupri.h"
#include "cpudeadline.h"
#include "cpuacct.h"

#ifdef CONFIG_SCHED_DEBUG
# define SCHED_WARN_ON(x)	WARN_ONCE(x, #x)
#else
# define SCHED_WARN_ON(x)	({ (void)(x), 0; })
#endif

struct rq;
struct cpuidle_state;

#define TASK_BITS (PID_MAX_DEFAULT + BITS_PER_LONG)

extern __read_mostly bool sched_predl;
extern unsigned int sched_capacity_margin_up[NR_CPUS];
extern unsigned int sched_capacity_margin_down[NR_CPUS];
extern unsigned int sched_capacity_margin_up_boosted[NR_CPUS];
extern unsigned int sched_capacity_margin_down_boosted[NR_CPUS];

#ifdef CONFIG_SCHED_WALT
extern unsigned int sched_ravg_window;
extern unsigned int walt_cpu_util_freq_divisor;

struct walt_sched_stats {
	int nr_big_tasks;
	u64 cumulative_runnable_avg_scaled;
	u64 pred_demands_sum_scaled;
};

struct cpu_cycle {
	u64 cycles;
	u64 time;
};

struct group_cpu_time {
	u64 curr_runnable_sum;
	u64 prev_runnable_sum;
	u64 nt_curr_runnable_sum;
	u64 nt_prev_runnable_sum;
};

struct load_subtractions {
	u64 window_start;
	u64 subs;
	u64 new_subs;
};

#define NUM_TRACKED_WINDOWS 2
#define NUM_LOAD_INDICES 1000

struct sched_cluster {
	raw_spinlock_t load_lock;
	struct list_head list;
	struct cpumask cpus;
	int id;
	int max_power_cost;
	int min_power_cost;
	int max_possible_capacity;
	int capacity;
	int efficiency; /* Differentiate cpus with different IPC capability */
	int load_scale_factor;
	unsigned int exec_scale_factor;
	/*
	 * max_freq = user maximum
	 * max_mitigated_freq = thermal defined maximum
	 * max_possible_freq = maximum supported by hardware
	 */
	unsigned int cur_freq, max_freq, max_mitigated_freq, min_freq;
	unsigned int max_possible_freq;
	bool freq_init_done;
	int dstate, dstate_wakeup_latency, dstate_wakeup_energy;
	unsigned int static_cluster_pwr_cost;
	int notifier_sent;
	bool wake_up_idle;
	u64 aggr_grp_load;
	u64 coloc_boost_load;
};

extern unsigned int sched_disable_window_stats;

extern struct timer_list sched_grp_timer;
#endif /* CONFIG_SCHED_WALT */

/* task_struct::on_rq states: */
#define TASK_ON_RQ_QUEUED	1
#define TASK_ON_RQ_MIGRATING	2

extern __read_mostly int scheduler_running;

extern unsigned long calc_load_update;
extern atomic_long_t calc_load_tasks;

extern void calc_global_load_tick(struct rq *this_rq);
extern long calc_load_fold_active(struct rq *this_rq, long adjust);

#ifdef CONFIG_SMP
extern void cpu_load_update_active(struct rq *this_rq);
extern void init_sched_groups_capacity(int cpu, struct sched_domain *sd);
#else
static inline void cpu_load_update_active(struct rq *this_rq) { }
#endif

extern bool energy_aware(void);

/*
 * Helpers for converting nanosecond timing to jiffy resolution
 */
#define NS_TO_JIFFIES(TIME)	((unsigned long)(TIME) / (NSEC_PER_SEC / HZ))

/*
 * Increase resolution of nice-level calculations for 64-bit architectures.
 * The extra resolution improves shares distribution and load balancing of
 * low-weight task groups (eg. nice +19 on an autogroup), deeper taskgroup
 * hierarchies, especially on larger systems. This is not a user-visible change
 * and does not change the user-interface for setting shares/weights.
 *
 * We increase resolution only if we have enough bits to allow this increased
 * resolution (i.e. 64bit). The costs for increasing resolution when 32bit are
 * pretty high and the returns do not justify the increased costs.
 *
 * Really only required when CONFIG_FAIR_GROUP_SCHED is also set, but to
 * increase coverage and consistency always enable it on 64bit platforms.
 */
#ifdef CONFIG_64BIT
# define NICE_0_LOAD_SHIFT	(SCHED_FIXEDPOINT_SHIFT + SCHED_FIXEDPOINT_SHIFT)
# define scale_load(w)		((w) << SCHED_FIXEDPOINT_SHIFT)
# define scale_load_down(w) \
({ \
	unsigned long __w = (w); \
	if (__w) \
		__w = max(2UL, __w >> SCHED_FIXEDPOINT_SHIFT); \
	__w; \
})
#else
# define NICE_0_LOAD_SHIFT	(SCHED_FIXEDPOINT_SHIFT)
# define scale_load(w)		(w)
# define scale_load_down(w)	(w)
#endif

/*
 * Task weight (visible to users) and its load (invisible to users) have
 * independent resolution, but they should be well calibrated. We use
 * scale_load() and scale_load_down(w) to convert between them. The
 * following must be true:
 *
 *  scale_load(sched_prio_to_weight[USER_PRIO(NICE_TO_PRIO(0))]) == NICE_0_LOAD
 *
 */
#define NICE_0_LOAD		(1L << NICE_0_LOAD_SHIFT)

/*
 * Single value that decides SCHED_DEADLINE internal math precision.
 * 10 -> just above 1us
 * 9  -> just above 0.5us
 */
#define DL_SCALE (10)

/*
 * These are the 'tuning knobs' of the scheduler:
 */

/*
 * single value that denotes runtime == period, ie unlimited time.
 */
#define RUNTIME_INF	((u64)~0ULL)

static inline int idle_policy(int policy)
{
	return policy == SCHED_IDLE;
}
static inline int fair_policy(int policy)
{
	return policy == SCHED_NORMAL || policy == SCHED_BATCH;
}

static inline int rt_policy(int policy)
{
	return policy == SCHED_FIFO || policy == SCHED_RR;
}

static inline int dl_policy(int policy)
{
	return policy == SCHED_DEADLINE;
}
static inline bool valid_policy(int policy)
{
	return idle_policy(policy) || fair_policy(policy) ||
		rt_policy(policy) || dl_policy(policy);
}

static inline int task_has_rt_policy(struct task_struct *p)
{
	return rt_policy(p->policy);
}

static inline int task_has_dl_policy(struct task_struct *p)
{
	return dl_policy(p->policy);
}

#define cap_scale(v, s) ((v)*(s) >> SCHED_CAPACITY_SHIFT)

/*
 * Tells if entity @a should preempt entity @b.
 */
static inline bool
dl_entity_preempt(struct sched_dl_entity *a, struct sched_dl_entity *b)
{
	return dl_time_before(a->deadline, b->deadline);
}

/*
 * This is the priority-queue data structure of the RT scheduling class:
 */
struct rt_prio_array {
	DECLARE_BITMAP(bitmap, MAX_RT_PRIO+1); /* include 1 bit for delimiter */
	struct list_head queue[MAX_RT_PRIO];
};

struct rt_bandwidth {
	/* nests inside the rq lock: */
	raw_spinlock_t		rt_runtime_lock;
	ktime_t			rt_period;
	u64			rt_runtime;
	struct hrtimer		rt_period_timer;
	unsigned int		rt_period_active;
};

void __dl_clear_params(struct task_struct *p);

struct dl_bandwidth {
	raw_spinlock_t dl_runtime_lock;
	u64 dl_runtime;
	u64 dl_period;
};

static inline int dl_bandwidth_enabled(void)
{
	return sysctl_sched_rt_runtime >= 0;
}

/*
 * To keep the bandwidth of -deadline tasks under control
 * we need some place where:
 *  - store the maximum -deadline bandwidth of each cpu;
 *  - cache the fraction of bandwidth that is currently allocated in
 *    each root domain;
 *
 * This is all done in the data structure below. It is similar to the
 * one used for RT-throttling (rt_bandwidth), with the main difference
 * that, since here we are only interested in admission control, we
 * do not decrease any runtime while the group "executes", neither we
 * need a timer to replenish it.
 *
 * With respect to SMP, bandwidth is given on a per root domain basis,
 * meaning that:
 *  - bw (< 100%) is the deadline bandwidth of each CPU;
 *  - total_bw is the currently allocated bandwidth in each root domain;
 */
struct dl_bw {
	raw_spinlock_t lock;
	u64 bw, total_bw;
};

static inline void __dl_update(struct dl_bw *dl_b, s64 bw);

static inline
void __dl_clear(struct dl_bw *dl_b, u64 tsk_bw, int cpus)
{
	dl_b->total_bw -= tsk_bw;
	__dl_update(dl_b, (s32)tsk_bw / cpus);
}

static inline
void __dl_add(struct dl_bw *dl_b, u64 tsk_bw, int cpus)
{
	dl_b->total_bw += tsk_bw;
	__dl_update(dl_b, -((s32)tsk_bw / cpus));
}

static inline
bool __dl_overflow(struct dl_bw *dl_b, int cpus, u64 old_bw, u64 new_bw)
{
	return dl_b->bw != -1 &&
	       dl_b->bw * cpus < dl_b->total_bw - old_bw + new_bw;
}

void dl_change_utilization(struct task_struct *p, u64 new_bw);
extern void init_dl_bw(struct dl_bw *dl_b);
extern int sched_dl_global_validate(void);
extern void sched_dl_do_global(void);
extern int sched_dl_overflow(struct task_struct *p, int policy,
			     const struct sched_attr *attr);
extern void __setparam_dl(struct task_struct *p, const struct sched_attr *attr);
extern void __getparam_dl(struct task_struct *p, struct sched_attr *attr);
extern bool __checkparam_dl(const struct sched_attr *attr);
extern void __dl_clear_params(struct task_struct *p);
extern bool dl_param_changed(struct task_struct *p, const struct sched_attr *attr);
extern int dl_task_can_attach(struct task_struct *p,
			      const struct cpumask *cs_cpus_allowed);
extern int dl_cpuset_cpumask_can_shrink(const struct cpumask *cur,
					const struct cpumask *trial);
extern bool dl_cpu_busy(unsigned int cpu);

#ifdef CONFIG_CGROUP_SCHED

#include <linux/cgroup.h>
#include <linux/psi.h>

struct cfs_rq;
struct rt_rq;

extern struct list_head task_groups;

struct cfs_bandwidth {
#ifdef CONFIG_CFS_BANDWIDTH
	raw_spinlock_t lock;
	ktime_t period;
	u64 quota, runtime;
	s64 hierarchical_quota;

	short idle, period_active;
	struct hrtimer period_timer, slack_timer;
	struct list_head throttled_cfs_rq;

	/* statistics */
	int nr_periods, nr_throttled;
	u64 throttled_time;

	bool distribute_running;
#endif
};

/* task group related information */
struct task_group {
	struct cgroup_subsys_state css;

#ifdef CONFIG_FAIR_GROUP_SCHED
	/* schedulable entities of this group on each cpu */
	struct sched_entity **se;
	/* runqueue "owned" by this group on each cpu */
	struct cfs_rq **cfs_rq;
	unsigned long shares;

#ifdef	CONFIG_SMP
	/*
	 * load_avg can be heavily contended at clock tick time, so put
	 * it in its own cacheline separated from the fields above which
	 * will also be accessed at each tick.
	 */
	atomic_long_t load_avg ____cacheline_aligned;
#endif
#endif

#ifdef CONFIG_RT_GROUP_SCHED
	struct sched_rt_entity **rt_se;
	struct rt_rq **rt_rq;

	struct rt_bandwidth rt_bandwidth;
#endif

	struct rcu_head rcu;
	struct list_head list;

	struct task_group *parent;
	struct list_head siblings;
	struct list_head children;

#ifdef CONFIG_SCHED_AUTOGROUP
	struct autogroup *autogroup;
#endif

	struct cfs_bandwidth cfs_bandwidth;
};

#ifdef CONFIG_FAIR_GROUP_SCHED
#define ROOT_TASK_GROUP_LOAD	NICE_0_LOAD

/*
 * A weight of 0 or 1 can cause arithmetics problems.
 * A weight of a cfs_rq is the sum of weights of which entities
 * are queued on this cfs_rq, so a weight of a entity should not be
 * too large, so as the shares value of a task group.
 * (The default weight is 1024 - so there's no practical
 *  limitation from this.)
 */
#define MIN_SHARES	(1UL <<  1)
#define MAX_SHARES	(1UL << 18)
#endif

typedef int (*tg_visitor)(struct task_group *, void *);

extern int walk_tg_tree_from(struct task_group *from,
			     tg_visitor down, tg_visitor up, void *data);

/*
 * Iterate the full tree, calling @down when first entering a node and @up when
 * leaving it for the final time.
 *
 * Caller must hold rcu_lock or sufficient equivalent.
 */
static inline int walk_tg_tree(tg_visitor down, tg_visitor up, void *data)
{
	return walk_tg_tree_from(&root_task_group, down, up, data);
}

extern int tg_nop(struct task_group *tg, void *data);

extern void free_fair_sched_group(struct task_group *tg);
extern int alloc_fair_sched_group(struct task_group *tg, struct task_group *parent);
extern void online_fair_sched_group(struct task_group *tg);
extern void unregister_fair_sched_group(struct task_group *tg);
extern void init_tg_cfs_entry(struct task_group *tg, struct cfs_rq *cfs_rq,
			struct sched_entity *se, int cpu,
			struct sched_entity *parent);
extern void init_cfs_bandwidth(struct cfs_bandwidth *cfs_b);

extern void __refill_cfs_bandwidth_runtime(struct cfs_bandwidth *cfs_b);
extern void start_cfs_bandwidth(struct cfs_bandwidth *cfs_b);
extern void unthrottle_cfs_rq(struct cfs_rq *cfs_rq);

extern void free_rt_sched_group(struct task_group *tg);
extern int alloc_rt_sched_group(struct task_group *tg, struct task_group *parent);
extern void init_tg_rt_entry(struct task_group *tg, struct rt_rq *rt_rq,
		struct sched_rt_entity *rt_se, int cpu,
		struct sched_rt_entity *parent);
extern int sched_group_set_rt_runtime(struct task_group *tg, long rt_runtime_us);
extern int sched_group_set_rt_period(struct task_group *tg, u64 rt_period_us);
extern long sched_group_rt_runtime(struct task_group *tg);
extern long sched_group_rt_period(struct task_group *tg);
extern int sched_rt_can_attach(struct task_group *tg, struct task_struct *tsk);

extern struct task_group *sched_create_group(struct task_group *parent);
extern void sched_online_group(struct task_group *tg,
			       struct task_group *parent);
extern void sched_destroy_group(struct task_group *tg);
extern void sched_offline_group(struct task_group *tg);

extern void sched_move_task(struct task_struct *tsk);

#ifdef CONFIG_FAIR_GROUP_SCHED
extern int sched_group_set_shares(struct task_group *tg, unsigned long shares);

#ifdef CONFIG_SMP
extern void set_task_rq_fair(struct sched_entity *se,
			     struct cfs_rq *prev, struct cfs_rq *next);
#else /* !CONFIG_SMP */
static inline void set_task_rq_fair(struct sched_entity *se,
			     struct cfs_rq *prev, struct cfs_rq *next) { }
#endif /* CONFIG_SMP */
#endif /* CONFIG_FAIR_GROUP_SCHED */

#else /* CONFIG_CGROUP_SCHED */

struct cfs_bandwidth { };

#endif	/* CONFIG_CGROUP_SCHED */

/* CFS-related fields in a runqueue */
struct cfs_rq {
	struct load_weight load;
	unsigned int nr_running, h_nr_running;

	u64 exec_clock;
	u64 min_vruntime;
#ifndef CONFIG_64BIT
	u64 min_vruntime_copy;
#endif

	struct rb_root_cached tasks_timeline;

	/*
	 * 'curr' points to currently running entity on this cfs_rq.
	 * It is set to NULL otherwise (i.e when none are currently running).
	 */
	struct sched_entity *curr, *next, *last, *skip;

#ifdef	CONFIG_SCHED_DEBUG
	unsigned int nr_spread_over;
#endif

#ifdef CONFIG_SMP
	/*
	 * CFS load tracking
	 */
	struct sched_avg avg;
	u64 runnable_load_sum;
	unsigned long runnable_load_avg;
#ifdef CONFIG_FAIR_GROUP_SCHED
	unsigned long tg_load_avg_contrib;
	unsigned long propagate_avg;
#endif
	atomic_long_t removed_load_avg, removed_util_avg;
#ifndef CONFIG_64BIT
	u64 load_last_update_time_copy;
#endif

#ifdef CONFIG_FAIR_GROUP_SCHED
	/*
	 *   h_load = weight * f(tg)
	 *
	 * Where f(tg) is the recursive weight fraction assigned to
	 * this group.
	 */
	unsigned long h_load;
	u64 last_h_load_update;
	struct sched_entity *h_load_next;
#endif /* CONFIG_FAIR_GROUP_SCHED */
#endif /* CONFIG_SMP */

#ifdef CONFIG_FAIR_GROUP_SCHED
	struct rq *rq;	/* cpu runqueue to which this cfs_rq is attached */

	/*
	 * leaf cfs_rqs are those that hold tasks (lowest schedulable entity in
	 * a hierarchy). Non-leaf lrqs hold other higher schedulable entities
	 * (like users, containers etc.)
	 *
	 * leaf_cfs_rq_list ties together list of leaf cfs_rq's in a cpu. This
	 * list is used during load balance.
	 */
	int on_list;
	struct list_head leaf_cfs_rq_list;
	struct task_group *tg;	/* group that "owns" this runqueue */

#ifdef CONFIG_SCHED_WALT
	struct walt_sched_stats walt_stats;
#endif

#ifdef CONFIG_CFS_BANDWIDTH
	int runtime_enabled;
	s64 runtime_remaining;

	u64 throttled_clock, throttled_clock_task;
	u64 throttled_clock_task_time;
	int throttled, throttle_count;
	struct list_head throttled_list;
#ifdef CONFIG_SCHED_WALT
	u64 cumulative_runnable_avg;
#endif /* CONFIG_SCHED_WALT */
#endif /* CONFIG_CFS_BANDWIDTH */
#endif /* CONFIG_FAIR_GROUP_SCHED */
};

static inline int rt_bandwidth_enabled(void)
{
	return sysctl_sched_rt_runtime >= 0;
}

/* RT IPI pull logic requires IRQ_WORK */
#if defined(CONFIG_IRQ_WORK) && defined(CONFIG_SMP)
# define HAVE_RT_PUSH_IPI
#endif

/* Real-Time classes' related field in a runqueue: */
struct rt_rq {
	struct rt_prio_array active;
	unsigned int rt_nr_running;
	unsigned int rr_nr_running;
#if defined CONFIG_SMP || defined CONFIG_RT_GROUP_SCHED
	struct {
		int curr; /* highest queued rt task prio */
#ifdef CONFIG_SMP
		int next; /* next highest */
#endif
	} highest_prio;
#endif
#ifdef CONFIG_SMP
	unsigned long rt_nr_migratory;
	unsigned long rt_nr_total;
	int overloaded;
	struct plist_head pushable_tasks;

	struct sched_avg avg;

#endif /* CONFIG_SMP */
	int rt_queued;

	int rt_throttled;
	u64 rt_time;
	u64 rt_runtime;
	/* Nests inside the rq lock: */
	raw_spinlock_t rt_runtime_lock;

#ifdef CONFIG_RT_GROUP_SCHED
	unsigned long rt_nr_boosted;

	struct rq *rq;
	struct task_group *tg;
#endif
};

/* Deadline class' related fields in a runqueue */
struct dl_rq {
	/* runqueue is an rbtree, ordered by deadline */
	struct rb_root_cached root;

	unsigned long dl_nr_running;

#ifdef CONFIG_SMP
	/*
	 * Deadline values of the currently executing and the
	 * earliest ready task on this rq. Caching these facilitates
	 * the decision wether or not a ready but not running task
	 * should migrate somewhere else.
	 */
	struct {
		u64 curr;
		u64 next;
	} earliest_dl;

	unsigned long dl_nr_migratory;
	int overloaded;

	/*
	 * Tasks on this rq that can be pushed away. They are kept in
	 * an rb-tree, ordered by tasks' deadlines, with caching
	 * of the leftmost (earliest deadline) element.
	 */
	struct rb_root_cached pushable_dl_tasks_root;
#else
	struct dl_bw dl_bw;
#endif
	/*
	 * "Active utilization" for this runqueue: increased when a
	 * task wakes up (becomes TASK_RUNNING) and decreased when a
	 * task blocks
	 */
	u64 running_bw;

	/*
	 * Utilization of the tasks "assigned" to this runqueue (including
	 * the tasks that are in runqueue and the tasks that executed on this
	 * CPU and blocked). Increased when a task moves to this runqueue, and
	 * decreased when the task moves away (migrates, changes scheduling
	 * policy, or terminates).
	 * This is needed to compute the "inactive utilization" for the
	 * runqueue (inactive utilization = this_bw - running_bw).
	 */
	u64 this_bw;
	u64 extra_bw;

	/*
	 * Inverse of the fraction of CPU utilization that can be reclaimed
	 * by the GRUB algorithm.
	 */
	u64 bw_ratio;
};

#ifdef CONFIG_SMP

static inline bool sched_asym_prefer(int a, int b)
{
	return arch_asym_cpu_priority(a) > arch_asym_cpu_priority(b);
}

struct max_cpu_capacity {
	raw_spinlock_t lock;
	unsigned long val;
	int cpu;
};

/*
 * We add the notion of a root-domain which will be used to define per-domain
 * variables. Each exclusive cpuset essentially defines an island domain by
 * fully partitioning the member cpus from any other cpuset. Whenever a new
 * exclusive cpuset is created, we also create and attach a new root-domain
 * object.
 *
 */
struct root_domain {
	atomic_t refcount;
	atomic_t rto_count;
	struct rcu_head rcu;
	cpumask_var_t span;
	cpumask_var_t online;

	/*
	 * Indicate pullable load on at least one CPU, e.g:
	 * - More than one runnable task
	 * - Running task is misfit
	 */
	int overload;

	/*
	 * The bit corresponding to a CPU gets set here if such CPU has more
	 * than one runnable -deadline task (as it is below for RT tasks).
	 */
	cpumask_var_t dlo_mask;
	atomic_t dlo_count;
	struct dl_bw dl_bw;
	struct cpudl cpudl;

#ifdef HAVE_RT_PUSH_IPI
	/*
	 * For IPI pull requests, loop across the rto_mask.
	 */
	struct irq_work rto_push_work;
	raw_spinlock_t rto_lock;
	/* These are only updated and read within rto_lock */
	int rto_loop;
	int rto_cpu;
	/* These atomics are updated outside of a lock */
	atomic_t rto_loop_next;
	atomic_t rto_loop_start;
#endif
	/*
	 * The "RT overload" flag: it gets set if a CPU has more than
	 * one runnable RT task.
	 */
	cpumask_var_t rto_mask;
	struct cpupri cpupri;

	/* Maximum cpu capacity in the system. */
	struct max_cpu_capacity max_cpu_capacity;

	/* First cpu with maximum and minimum original capacity */
	int max_cap_orig_cpu, min_cap_orig_cpu;
	/* First cpu with mid capacity */
	int mid_cap_orig_cpu;
};

extern struct root_domain def_root_domain;
extern struct mutex sched_domains_mutex;

extern void init_defrootdomain(void);
extern void init_max_cpu_capacity(struct max_cpu_capacity *mcc);
extern int sched_init_domains(const struct cpumask *cpu_map);
extern void rq_attach_root(struct rq *rq, struct root_domain *rd);
extern void sched_get_rd(struct root_domain *rd);
extern void sched_put_rd(struct root_domain *rd);

#ifdef HAVE_RT_PUSH_IPI
extern void rto_push_irq_work_func(struct irq_work *work);
#endif
#endif /* CONFIG_SMP */

/*
 * This is the main, per-CPU runqueue data structure.
 *
 * Locking rule: those places that want to lock multiple runqueues
 * (such as the load balancing or the thread migration code), lock
 * acquire operations must be ordered by ascending &runqueue.
 */
struct rq {
	/* runqueue lock: */
	raw_spinlock_t lock;

	/*
	 * nr_running and cpu_load should be in the same cacheline because
	 * remote CPUs use both these fields when doing load calculation.
	 */
	unsigned int nr_running;
#ifdef CONFIG_NUMA_BALANCING
	unsigned int nr_numa_running;
	unsigned int nr_preferred_running;
#endif
	#define CPU_LOAD_IDX_MAX 5
	unsigned long cpu_load[CPU_LOAD_IDX_MAX];
#ifdef CONFIG_NO_HZ_COMMON
#ifdef CONFIG_SMP
	unsigned long last_load_update_tick;
	unsigned long last_blocked_load_update_tick;
#endif /* CONFIG_SMP */
	unsigned long nohz_flags;
#endif /* CONFIG_NO_HZ_COMMON */
#ifdef CONFIG_NO_HZ_FULL
	unsigned long last_sched_tick;
#endif
	/* capture load from *all* tasks on this cpu: */
	struct load_weight load;
	unsigned long nr_load_updates;
	u64 nr_switches;

	struct cfs_rq cfs;
	struct rt_rq rt;
	struct dl_rq dl;

#ifdef CONFIG_FAIR_GROUP_SCHED
	/* list of leaf cfs_rq on this cpu: */
	struct list_head leaf_cfs_rq_list;
	struct list_head *tmp_alone_branch;
#endif /* CONFIG_FAIR_GROUP_SCHED */

	/*
	 * This is part of a global counter where only the total sum
	 * over all CPUs matters. A task can increase this counter on
	 * one CPU and if it got migrated afterwards it may decrease
	 * it on another CPU. Always updated under the runqueue lock:
	 */
	unsigned long nr_uninterruptible;

	struct task_struct *curr, *idle, *stop;
	unsigned long next_balance;
	struct mm_struct *prev_mm;

	unsigned int clock_update_flags;
	u64 clock;
	u64 clock_task;

	atomic_t nr_iowait;

#ifdef CONFIG_SMP
	struct root_domain *rd;
	struct sched_domain *sd;

	unsigned long cpu_capacity;
	unsigned long cpu_capacity_orig;

	struct callback_head *balance_callback;

	unsigned char idle_balance;

	unsigned long misfit_task_load;

	/* For active balancing */
	int active_balance;
	int push_cpu;
	struct task_struct *push_task;
	struct cpu_stop_work active_balance_work;
	/* cpu of this runqueue: */
	int cpu;
	int online;

	struct list_head cfs_tasks;

	u64 rt_avg;
	u64 age_stamp;
	u64 idle_stamp;
	u64 avg_idle;

	/* This is used to determine avg_idle's max value */
	u64 max_idle_balance_cost;
#endif

#ifdef CONFIG_SCHED_WALT
	struct sched_cluster *cluster;
	struct cpumask freq_domain_cpumask;
	struct walt_sched_stats walt_stats;

	int cstate, wakeup_latency, wakeup_energy;
	u64 window_start;
	s64 cum_window_start;
	unsigned long walt_flags;

	u64 cur_irqload;
	u64 avg_irqload;
	u64 irqload_ts;
	unsigned int static_cpu_pwr_cost;
	struct task_struct *ed_task;
	struct cpu_cycle cc;
	u64 old_busy_time, old_busy_time_group;
	u64 old_estimated_time;
	u64 curr_runnable_sum;
	u64 prev_runnable_sum;
	u64 nt_curr_runnable_sum;
	u64 nt_prev_runnable_sum;
	u64 cum_window_demand_scaled;
	struct group_cpu_time grp_time;
	struct load_subtractions load_subs[NUM_TRACKED_WINDOWS];
	DECLARE_BITMAP_ARRAY(top_tasks_bitmap,
			NUM_TRACKED_WINDOWS, NUM_LOAD_INDICES);
	u8 *top_tasks[NUM_TRACKED_WINDOWS];
	u8 curr_table;
	int prev_top;
	int curr_top;
	bool notif_pending;
	u64 last_cc_update;
	u64 cycles;
#endif /* CONFIG_SCHED_WALT */

#ifdef CONFIG_IRQ_TIME_ACCOUNTING
	u64 prev_irq_time;
#endif
#ifdef CONFIG_PARAVIRT
	u64 prev_steal_time;
#endif
#ifdef CONFIG_PARAVIRT_TIME_ACCOUNTING
	u64 prev_steal_time_rq;
#endif

	/* calc_load related fields */
	unsigned long calc_load_update;
	long calc_load_active;

#ifdef CONFIG_SCHED_HRTICK
#ifdef CONFIG_SMP
	int hrtick_csd_pending;
	call_single_data_t hrtick_csd;
#endif
	struct hrtimer hrtick_timer;
#endif

#ifdef CONFIG_SCHEDSTATS
	/* latency stats */
	struct sched_info rq_sched_info;
	unsigned long long rq_cpu_time;
	/* could above be rq->cfs_rq.exec_clock + rq->rt_rq.rt_runtime ? */

	/* sys_sched_yield() stats */
	unsigned int yld_count;

	/* schedule() stats */
	unsigned int sched_count;
	unsigned int sched_goidle;

	/* try_to_wake_up() stats */
	unsigned int ttwu_count;
	unsigned int ttwu_local;
#endif

#ifdef CONFIG_SMP
	struct llist_head wake_list;
#endif

#ifdef CONFIG_CPU_IDLE
	/* Must be inspected within a rcu lock section */
	struct cpuidle_state *idle_state;
	int idle_state_idx;
#endif
};

static inline int cpu_of(struct rq *rq)
{
#ifdef CONFIG_SMP
	return rq->cpu;
#else
	return 0;
#endif
}


#ifdef CONFIG_SCHED_SMT
extern void __update_idle_core(struct rq *rq);

static inline void update_idle_core(struct rq *rq)
{
	if (static_branch_unlikely(&sched_smt_present))
		__update_idle_core(rq);
}

#else
static inline void update_idle_core(struct rq *rq) { }
#endif

DECLARE_PER_CPU_SHARED_ALIGNED(struct rq, runqueues);

#define cpu_rq(cpu)		(&per_cpu(runqueues, (cpu)))
#define this_rq()		this_cpu_ptr(&runqueues)
#define task_rq(p)		cpu_rq(task_cpu(p))
#define cpu_curr(cpu)		(cpu_rq(cpu)->curr)
#define raw_rq()		raw_cpu_ptr(&runqueues)

extern void update_rq_clock(struct rq *rq);

static inline u64 __rq_clock_broken(struct rq *rq)
{
	return READ_ONCE(rq->clock);
}

/*
 * rq::clock_update_flags bits
 *
 * %RQCF_REQ_SKIP - will request skipping of clock update on the next
 *  call to __schedule(). This is an optimisation to avoid
 *  neighbouring rq clock updates.
 *
 * %RQCF_ACT_SKIP - is set from inside of __schedule() when skipping is
 *  in effect and calls to update_rq_clock() are being ignored.
 *
 * %RQCF_UPDATED - is a debug flag that indicates whether a call has been
 *  made to update_rq_clock() since the last time rq::lock was pinned.
 *
 * If inside of __schedule(), clock_update_flags will have been
 * shifted left (a left shift is a cheap operation for the fast path
 * to promote %RQCF_REQ_SKIP to %RQCF_ACT_SKIP), so you must use,
 *
 *	if (rq-clock_update_flags >= RQCF_UPDATED)
 *
 * to check if %RQCF_UPADTED is set. It'll never be shifted more than
 * one position though, because the next rq_unpin_lock() will shift it
 * back.
 */
#define RQCF_REQ_SKIP	0x01
#define RQCF_ACT_SKIP	0x02
#define RQCF_UPDATED	0x04

static inline void assert_clock_updated(struct rq *rq)
{
	/*
	 * The only reason for not seeing a clock update since the
	 * last rq_pin_lock() is if we're currently skipping updates.
	 */
	SCHED_WARN_ON(rq->clock_update_flags < RQCF_ACT_SKIP);
}

static inline u64 rq_clock(struct rq *rq)
{
	lockdep_assert_held(&rq->lock);
	assert_clock_updated(rq);

	return rq->clock;
}

static inline u64 rq_clock_task(struct rq *rq)
{
	lockdep_assert_held(&rq->lock);
	assert_clock_updated(rq);

	return rq->clock_task;
}

static inline void rq_clock_skip_update(struct rq *rq, bool skip)
{
	lockdep_assert_held(&rq->lock);
	if (skip)
		rq->clock_update_flags |= RQCF_REQ_SKIP;
	else
		rq->clock_update_flags &= ~RQCF_REQ_SKIP;
}

struct rq_flags {
	unsigned long flags;
	struct pin_cookie cookie;
#ifdef CONFIG_SCHED_DEBUG
	/*
	 * A copy of (rq::clock_update_flags & RQCF_UPDATED) for the
	 * current pin context is stashed here in case it needs to be
	 * restored in rq_repin_lock().
	 */
	unsigned int clock_update_flags;
#endif
};

static inline void rq_pin_lock(struct rq *rq, struct rq_flags *rf)
{
	rf->cookie = lockdep_pin_lock(&rq->lock);

#ifdef CONFIG_SCHED_DEBUG
	rq->clock_update_flags &= (RQCF_REQ_SKIP|RQCF_ACT_SKIP);
	rf->clock_update_flags = 0;
#endif
}

static inline void rq_unpin_lock(struct rq *rq, struct rq_flags *rf)
{
#ifdef CONFIG_SCHED_DEBUG
	if (rq->clock_update_flags > RQCF_ACT_SKIP)
		rf->clock_update_flags = RQCF_UPDATED;
#endif

	lockdep_unpin_lock(&rq->lock, rf->cookie);
}

static inline void rq_repin_lock(struct rq *rq, struct rq_flags *rf)
{
	lockdep_repin_lock(&rq->lock, rf->cookie);

#ifdef CONFIG_SCHED_DEBUG
	/*
	 * Restore the value we stashed in @rf for this pin context.
	 */
	rq->clock_update_flags |= rf->clock_update_flags;
#endif
}

struct rq *__task_rq_lock(struct task_struct *p, struct rq_flags *rf)
	__acquires(rq->lock);

struct rq *task_rq_lock(struct task_struct *p, struct rq_flags *rf)
	__acquires(p->pi_lock)
	__acquires(rq->lock);

static inline void __task_rq_unlock(struct rq *rq, struct rq_flags *rf)
	__releases(rq->lock)
{
	rq_unpin_lock(rq, rf);
	raw_spin_unlock(&rq->lock);
}

static inline void
task_rq_unlock(struct rq *rq, struct task_struct *p, struct rq_flags *rf)
	__releases(rq->lock)
	__releases(p->pi_lock)
{
	rq_unpin_lock(rq, rf);
	raw_spin_unlock(&rq->lock);
	raw_spin_unlock_irqrestore(&p->pi_lock, rf->flags);
}

static inline void
rq_lock_irqsave(struct rq *rq, struct rq_flags *rf)
	__acquires(rq->lock)
{
	raw_spin_lock_irqsave(&rq->lock, rf->flags);
	rq_pin_lock(rq, rf);
}

static inline void
rq_lock_irq(struct rq *rq, struct rq_flags *rf)
	__acquires(rq->lock)
{
	raw_spin_lock_irq(&rq->lock);
	rq_pin_lock(rq, rf);
}

static inline void
rq_lock(struct rq *rq, struct rq_flags *rf)
	__acquires(rq->lock)
{
	raw_spin_lock(&rq->lock);
	rq_pin_lock(rq, rf);
}

static inline void
rq_relock(struct rq *rq, struct rq_flags *rf)
	__acquires(rq->lock)
{
	raw_spin_lock(&rq->lock);
	rq_repin_lock(rq, rf);
}

static inline void
rq_unlock_irqrestore(struct rq *rq, struct rq_flags *rf)
	__releases(rq->lock)
{
	rq_unpin_lock(rq, rf);
	raw_spin_unlock_irqrestore(&rq->lock, rf->flags);
}

static inline void
rq_unlock_irq(struct rq *rq, struct rq_flags *rf)
	__releases(rq->lock)
{
	rq_unpin_lock(rq, rf);
	raw_spin_unlock_irq(&rq->lock);
}

static inline void
rq_unlock(struct rq *rq, struct rq_flags *rf)
	__releases(rq->lock)
{
	rq_unpin_lock(rq, rf);
	raw_spin_unlock(&rq->lock);
}

static inline struct rq *
this_rq_lock_irq(struct rq_flags *rf)
	__acquires(rq->lock)
{
	struct rq *rq;

	local_irq_disable();
	rq = this_rq();
	rq_lock(rq, rf);
	return rq;
}

#ifdef CONFIG_NUMA
enum numa_topology_type {
	NUMA_DIRECT,
	NUMA_GLUELESS_MESH,
	NUMA_BACKPLANE,
};
extern enum numa_topology_type sched_numa_topology_type;
extern int sched_max_numa_distance;
extern bool find_numa_distance(int distance);
#endif

#ifdef CONFIG_NUMA
extern void sched_init_numa(void);
extern void sched_domains_numa_masks_set(unsigned int cpu);
extern void sched_domains_numa_masks_clear(unsigned int cpu);
#else
static inline void sched_init_numa(void) { }
static inline void sched_domains_numa_masks_set(unsigned int cpu) { }
static inline void sched_domains_numa_masks_clear(unsigned int cpu) { }
#endif

#ifdef CONFIG_NUMA_BALANCING
/* The regions in numa_faults array from task_struct */
enum numa_faults_stats {
	NUMA_MEM = 0,
	NUMA_CPU,
	NUMA_MEMBUF,
	NUMA_CPUBUF
};
extern void sched_setnuma(struct task_struct *p, int node);
extern int migrate_task_to(struct task_struct *p, int cpu);
#endif /* CONFIG_NUMA_BALANCING */
extern int migrate_swap(struct task_struct *cur, struct task_struct *p);

#ifdef CONFIG_SMP

static inline void
queue_balance_callback(struct rq *rq,
		       struct callback_head *head,
		       void (*func)(struct rq *rq))
{
	lockdep_assert_held(&rq->lock);

	if (unlikely(head->next))
		return;

	head->func = (void (*)(struct callback_head *))func;
	head->next = rq->balance_callback;
	rq->balance_callback = head;
}

extern void sched_ttwu_pending(void);

#define rcu_dereference_check_sched_domain(p) \
	rcu_dereference_check((p), \
			      lockdep_is_held(&sched_domains_mutex))

/*
 * The domain tree (rq->sd) is protected by RCU's quiescent state transition.
 * See detach_destroy_domains: synchronize_sched for details.
 *
 * The domain tree of any CPU may only be accessed from within
 * preempt-disabled sections.
 */
#define for_each_domain(cpu, __sd) \
	for (__sd = rcu_dereference_check_sched_domain(cpu_rq(cpu)->sd); \
			__sd; __sd = __sd->parent)

#define for_each_lower_domain(sd) for (; sd; sd = sd->child)

/**
 * highest_flag_domain - Return highest sched_domain containing flag.
 * @cpu:	The cpu whose highest level of sched domain is to
 *		be returned.
 * @flag:	The flag to check for the highest sched_domain
 *		for the given cpu.
 *
 * Returns the highest sched_domain of a cpu which contains the given flag.
 */
static inline struct sched_domain *highest_flag_domain(int cpu, int flag)
{
	struct sched_domain *sd, *hsd = NULL;

	for_each_domain(cpu, sd) {
		if (!(sd->flags & flag))
			break;
		hsd = sd;
	}

	return hsd;
}

static inline struct sched_domain *lowest_flag_domain(int cpu, int flag)
{
	struct sched_domain *sd;

	for_each_domain(cpu, sd) {
		if (sd->flags & flag)
			break;
	}

	return sd;
}

DECLARE_PER_CPU(struct sched_domain *, sd_llc);
DECLARE_PER_CPU(int, sd_llc_size);
DECLARE_PER_CPU(int, sd_llc_id);
DECLARE_PER_CPU(struct sched_domain_shared *, sd_llc_shared);
DECLARE_PER_CPU(struct sched_domain *, sd_numa);
DECLARE_PER_CPU(struct sched_domain *, sd_asym);
DECLARE_PER_CPU(struct sched_domain *, sd_ea);
DECLARE_PER_CPU(struct sched_domain *, sd_scs);
extern struct static_key_false sched_asym_cpucapacity;

struct sched_group_capacity {
	atomic_t ref;
	/*
	 * CPU capacity of this group, SCHED_CAPACITY_SCALE being max capacity
	 * for a single CPU.
	 */
	unsigned long capacity;
	unsigned long min_capacity; /* Min per-CPU capacity in group */
	unsigned long max_capacity; /* Max per-CPU capacity in group */
	unsigned long next_update;
	int imbalance; /* XXX unrelated to capacity but shared group state */

#ifdef CONFIG_SCHED_DEBUG
	int id;
#endif

	unsigned long cpumask[0]; /* balance mask */
};

struct sched_group {
	struct sched_group *next;	/* Must be a circular list */
	atomic_t ref;

	unsigned int group_weight;
	struct sched_group_capacity *sgc;
	int asym_prefer_cpu;		/* cpu of highest priority in group */
	const struct sched_group_energy *sge;

	/*
	 * The CPUs this group covers.
	 *
	 * NOTE: this field is variable length. (Allocated dynamically
	 * by attaching extra space to the end of the structure,
	 * depending on how many CPUs the kernel has booted up with)
	 */
	unsigned long cpumask[0];
};

static inline struct cpumask *sched_group_span(struct sched_group *sg)
{
	return to_cpumask(sg->cpumask);
}

/*
 * See build_balance_mask().
 */
static inline struct cpumask *group_balance_mask(struct sched_group *sg)
{
	return to_cpumask(sg->sgc->cpumask);
}

/**
 * group_first_cpu - Returns the first cpu in the cpumask of a sched_group.
 * @group: The group whose first cpu is to be returned.
 */
static inline unsigned int group_first_cpu(struct sched_group *group)
{
	return cpumask_first(sched_group_span(group));
}

extern int group_balance_cpu(struct sched_group *sg);

#if defined(CONFIG_SCHED_DEBUG) && defined(CONFIG_SYSCTL)
void register_sched_domain_sysctl(void);
void dirty_sched_domain_sysctl(int cpu);
void unregister_sched_domain_sysctl(void);
#else
static inline void register_sched_domain_sysctl(void)
{
}
static inline void dirty_sched_domain_sysctl(int cpu)
{
}
static inline void unregister_sched_domain_sysctl(void)
{
}
#endif

#else

static inline void sched_ttwu_pending(void) { }

#endif /* CONFIG_SMP */

#include "stats.h"
#include "autogroup.h"

#ifdef CONFIG_CGROUP_SCHED

/*
 * Return the group to which this tasks belongs.
 *
 * We cannot use task_css() and friends because the cgroup subsystem
 * changes that value before the cgroup_subsys::attach() method is called,
 * therefore we cannot pin it and might observe the wrong value.
 *
 * The same is true for autogroup's p->signal->autogroup->tg, the autogroup
 * core changes this before calling sched_move_task().
 *
 * Instead we use a 'copy' which is updated from sched_move_task() while
 * holding both task_struct::pi_lock and rq::lock.
 */
static inline struct task_group *task_group(struct task_struct *p)
{
	return p->sched_task_group;
}

/* Change a task's cfs_rq and parent entity if it moves across CPUs/groups */
static inline void set_task_rq(struct task_struct *p, unsigned int cpu)
{
#if defined(CONFIG_FAIR_GROUP_SCHED) || defined(CONFIG_RT_GROUP_SCHED)
	struct task_group *tg = task_group(p);
#endif

#ifdef CONFIG_FAIR_GROUP_SCHED
	set_task_rq_fair(&p->se, p->se.cfs_rq, tg->cfs_rq[cpu]);
	p->se.cfs_rq = tg->cfs_rq[cpu];
	p->se.parent = tg->se[cpu];
#endif

#ifdef CONFIG_RT_GROUP_SCHED
	p->rt.rt_rq  = tg->rt_rq[cpu];
	p->rt.parent = tg->rt_se[cpu];
#endif
}

#else /* CONFIG_CGROUP_SCHED */

static inline void set_task_rq(struct task_struct *p, unsigned int cpu) { }
static inline struct task_group *task_group(struct task_struct *p)
{
	return NULL;
}

#endif /* CONFIG_CGROUP_SCHED */

static inline void __set_task_cpu(struct task_struct *p, unsigned int cpu)
{
	set_task_rq(p, cpu);
#ifdef CONFIG_SMP
	/*
	 * After ->cpu is set up to a new value, task_rq_lock(p, ...) can be
	 * successfuly executed on another CPU. We must ensure that updates of
	 * per-task data have been completed by this moment.
	 */
	smp_wmb();
#ifdef CONFIG_THREAD_INFO_IN_TASK
	WRITE_ONCE(p->cpu, cpu);
#else
	WRITE_ONCE(task_thread_info(p)->cpu, cpu);
#endif
	p->wake_cpu = cpu;
#endif
}

/*
 * Tunables that become constants when CONFIG_SCHED_DEBUG is off:
 */
#ifdef CONFIG_SCHED_DEBUG
# include <linux/static_key.h>
# define const_debug __read_mostly
#else
# define const_debug const
#endif

extern const_debug unsigned int sysctl_sched_features;

#define SCHED_FEAT(name, enabled)	\
	__SCHED_FEAT_##name ,

enum {
#include "features.h"
	__SCHED_FEAT_NR,
};

#undef SCHED_FEAT

#if defined(CONFIG_SCHED_DEBUG) && defined(HAVE_JUMP_LABEL)
#define SCHED_FEAT(name, enabled)					\
static __always_inline bool static_branch_##name(struct static_key *key) \
{									\
	return static_key_##enabled(key);				\
}

#include "features.h"

#undef SCHED_FEAT

extern struct static_key sched_feat_keys[__SCHED_FEAT_NR];
#define sched_feat(x) (static_branch_##x(&sched_feat_keys[__SCHED_FEAT_##x]))
#else /* !(SCHED_DEBUG && HAVE_JUMP_LABEL) */
#define sched_feat(x) !!(sysctl_sched_features & (1UL << __SCHED_FEAT_##x))
#endif /* SCHED_DEBUG && HAVE_JUMP_LABEL */

extern struct static_key_false sched_numa_balancing;
extern struct static_key_false sched_schedstats;

static inline u64 global_rt_period(void)
{
	return (u64)sysctl_sched_rt_period * NSEC_PER_USEC;
}

static inline u64 global_rt_runtime(void)
{
	if (sysctl_sched_rt_runtime < 0)
		return RUNTIME_INF;

	return (u64)sysctl_sched_rt_runtime * NSEC_PER_USEC;
}

static inline int task_current(struct rq *rq, struct task_struct *p)
{
	return rq->curr == p;
}

static inline int task_running(struct rq *rq, struct task_struct *p)
{
#ifdef CONFIG_SMP
	return p->on_cpu;
#else
	return task_current(rq, p);
#endif
}

static inline int task_on_rq_queued(struct task_struct *p)
{
	return p->on_rq == TASK_ON_RQ_QUEUED;
}

static inline int task_on_rq_migrating(struct task_struct *p)
{
	return READ_ONCE(p->on_rq) == TASK_ON_RQ_MIGRATING;
}

#ifndef prepare_arch_switch
# define prepare_arch_switch(next)	do { } while (0)
#endif
#ifndef finish_arch_post_lock_switch
# define finish_arch_post_lock_switch()	do { } while (0)
#endif

static inline void prepare_lock_switch(struct rq *rq, struct task_struct *next)
{
#ifdef CONFIG_SMP
	/*
	 * We can optimise this out completely for !SMP, because the
	 * SMP rebalancing from interrupt is the only thing that cares
	 * here.
	 */
	next->on_cpu = 1;
#endif
}

static inline void finish_lock_switch(struct rq *rq, struct task_struct *prev)
{
#ifdef CONFIG_SMP
	/*
	 * After ->on_cpu is cleared, the task can be moved to a different CPU.
	 * We must ensure this doesn't happen until the switch is completely
	 * finished.
	 *
	 * In particular, the load of prev->state in finish_task_switch() must
	 * happen before this.
	 *
	 * Pairs with the smp_cond_load_acquire() in try_to_wake_up().
	 */
	smp_store_release(&prev->on_cpu, 0);
#endif
#ifdef CONFIG_DEBUG_SPINLOCK
	/* this is a valid case when another task releases the spinlock */
	rq->lock.owner = current;
#endif
	/*
	 * If we are tracking spinlock dependencies then we have to
	 * fix up the runqueue lock - which gets 'carried over' from
	 * prev into current:
	 */
	spin_acquire(&rq->lock.dep_map, 0, 0, _THIS_IP_);

	raw_spin_unlock_irq(&rq->lock);
}

/*
 * wake flags
 */
#define WF_SYNC		0x01		/* waker goes to sleep after wakeup */
#define WF_FORK		0x02		/* child wakeup after fork */
#define WF_MIGRATED	0x4		/* internal use, task got migrated */

/*
 * To aid in avoiding the subversion of "niceness" due to uneven distribution
 * of tasks with abnormal "nice" values across CPUs the contribution that
 * each task makes to its run queue's load is weighted according to its
 * scheduling class and "nice" value. For SCHED_NORMAL tasks this is just a
 * scaled version of the new time slice allocation that they receive on time
 * slice expiry etc.
 */

#define WEIGHT_IDLEPRIO                3
#define WMULT_IDLEPRIO         1431655765

extern const int sched_prio_to_weight[40];
extern const u32 sched_prio_to_wmult[40];

/*
 * {de,en}queue flags:
 *
 * DEQUEUE_SLEEP  - task is no longer runnable
 * ENQUEUE_WAKEUP - task just became runnable
 *
 * SAVE/RESTORE - an otherwise spurious dequeue/enqueue, done to ensure tasks
 *                are in a known state which allows modification. Such pairs
 *                should preserve as much state as possible.
 *
 * MOVE - paired with SAVE/RESTORE, explicitly does not preserve the location
 *        in the runqueue.
 *
 * ENQUEUE_HEAD      - place at front of runqueue (tail if not specified)
 * ENQUEUE_REPLENISH - CBS (replenish runtime and postpone deadline)
 * ENQUEUE_MIGRATED  - the task was migrated during wakeup
 *
 */

#define DEQUEUE_SLEEP		0x01
#define DEQUEUE_SAVE		0x02 /* matches ENQUEUE_RESTORE */
#define DEQUEUE_MOVE		0x04 /* matches ENQUEUE_MOVE */
#define DEQUEUE_NOCLOCK		0x08 /* matches ENQUEUE_NOCLOCK */

#define ENQUEUE_WAKEUP		0x01
#define ENQUEUE_RESTORE		0x02
#define ENQUEUE_MOVE		0x04
#define ENQUEUE_NOCLOCK		0x08

#define ENQUEUE_HEAD		0x10
#define ENQUEUE_REPLENISH	0x20
#ifdef CONFIG_SMP
#define ENQUEUE_MIGRATED	0x40
#else
#define ENQUEUE_MIGRATED	0x00
#endif

#define RETRY_TASK		((void *)-1UL)

struct sched_class {
	const struct sched_class *next;

	void (*enqueue_task) (struct rq *rq, struct task_struct *p, int flags);
	void (*dequeue_task) (struct rq *rq, struct task_struct *p, int flags);
	void (*yield_task) (struct rq *rq);
	bool (*yield_to_task) (struct rq *rq, struct task_struct *p, bool preempt);

	void (*check_preempt_curr) (struct rq *rq, struct task_struct *p, int flags);

	/*
	 * It is the responsibility of the pick_next_task() method that will
	 * return the next task to call put_prev_task() on the @prev task or
	 * something equivalent.
	 *
	 * May return RETRY_TASK when it finds a higher prio class has runnable
	 * tasks.
	 */
	struct task_struct * (*pick_next_task) (struct rq *rq,
						struct task_struct *prev,
						struct rq_flags *rf);
	void (*put_prev_task) (struct rq *rq, struct task_struct *p);

#ifdef CONFIG_SMP
	int  (*select_task_rq)(struct task_struct *p, int task_cpu, int sd_flag, int flags,
			       int subling_count_hint);
	void (*migrate_task_rq)(struct task_struct *p);

	void (*task_woken) (struct rq *this_rq, struct task_struct *task);

	void (*set_cpus_allowed)(struct task_struct *p,
				 const struct cpumask *newmask);

	void (*rq_online)(struct rq *rq);
	void (*rq_offline)(struct rq *rq);
#endif

	void (*set_curr_task) (struct rq *rq);
	void (*task_tick) (struct rq *rq, struct task_struct *p, int queued);
	void (*task_fork) (struct task_struct *p);
	void (*task_dead) (struct task_struct *p);

	/*
	 * The switched_from() call is allowed to drop rq->lock, therefore we
	 * cannot assume the switched_from/switched_to pair is serliazed by
	 * rq->lock. They are however serialized by p->pi_lock.
	 */
	void (*switched_from) (struct rq *this_rq, struct task_struct *task);
	void (*switched_to) (struct rq *this_rq, struct task_struct *task);
	void (*prio_changed) (struct rq *this_rq, struct task_struct *task,
			     int oldprio);

	unsigned int (*get_rr_interval) (struct rq *rq,
					 struct task_struct *task);

	void (*update_curr) (struct rq *rq);

#define TASK_SET_GROUP  0
#define TASK_MOVE_GROUP	1

#ifdef CONFIG_FAIR_GROUP_SCHED
	void (*task_change_group) (struct task_struct *p, int type);
#endif

#ifdef CONFIG_SCHED_WALT
	void (*fixup_walt_sched_stats)(struct rq *rq, struct task_struct *p,
				       u16 updated_demand_scaled,
				       u16 updated_pred_demand_scaled);
#endif
};


static inline void put_prev_task(struct rq *rq, struct task_struct *prev)
{
	prev->sched_class->put_prev_task(rq, prev);
}

static inline void set_curr_task(struct rq *rq, struct task_struct *curr)
{
	curr->sched_class->set_curr_task(rq);
}

#ifdef CONFIG_SMP
#define sched_class_highest (&stop_sched_class)
#else
#define sched_class_highest (&dl_sched_class)
#endif
#define for_each_class(class) \
   for (class = sched_class_highest; class; class = class->next)

extern const struct sched_class stop_sched_class;
extern const struct sched_class dl_sched_class;
extern const struct sched_class rt_sched_class;
extern const struct sched_class fair_sched_class;
extern const struct sched_class idle_sched_class;


#ifdef CONFIG_SMP

extern void update_group_capacity(struct sched_domain *sd, int cpu);

extern void trigger_load_balance(struct rq *rq);

extern void set_cpus_allowed_common(struct task_struct *p, const struct cpumask *new_mask);

bool __cpu_overutilized(int cpu, int delta);
bool cpu_overutilized(int cpu);

#endif

#ifdef CONFIG_CPU_IDLE
static inline void idle_set_state(struct rq *rq,
				  struct cpuidle_state *idle_state)
{
	rq->idle_state = idle_state;
}

static inline struct cpuidle_state *idle_get_state(struct rq *rq)
{
	SCHED_WARN_ON(!rcu_read_lock_held());
	return rq->idle_state;
}

static inline void idle_set_state_idx(struct rq *rq, int idle_state_idx)
{
	rq->idle_state_idx = idle_state_idx;
}

static inline int idle_get_state_idx(struct rq *rq)
{
	WARN_ON(!rcu_read_lock_held());

	if (rq->nr_running || cpu_of(rq) == raw_smp_processor_id())
		return -1;

	return rq->idle_state_idx;
}
#else
static inline void idle_set_state(struct rq *rq,
				  struct cpuidle_state *idle_state)
{
}

static inline struct cpuidle_state *idle_get_state(struct rq *rq)
{
	return NULL;
}

static inline void idle_set_state_idx(struct rq *rq, int idle_state_idx)
{
}

static inline int idle_get_state_idx(struct rq *rq)
{
	return -1;
}
#endif

extern void schedule_idle(void);

extern void sysrq_sched_debug_show(void);
extern void sched_init_granularity(void);
extern void update_max_interval(void);

extern void init_sched_dl_class(void);
extern void init_sched_rt_class(void);
extern void init_sched_fair_class(void);

extern void resched_curr(struct rq *rq);
extern void resched_cpu(int cpu);

extern struct rt_bandwidth def_rt_bandwidth;
extern void init_rt_bandwidth(struct rt_bandwidth *rt_b, u64 period, u64 runtime);

extern struct dl_bandwidth def_dl_bandwidth;
extern void init_dl_bandwidth(struct dl_bandwidth *dl_b, u64 period, u64 runtime);
extern void init_dl_task_timer(struct sched_dl_entity *dl_se);
extern void init_dl_inactive_task_timer(struct sched_dl_entity *dl_se);
extern void init_dl_rq_bw_ratio(struct dl_rq *dl_rq);

#define BW_SHIFT	20
#define BW_UNIT		(1 << BW_SHIFT)
#define RATIO_SHIFT	8
unsigned long to_ratio(u64 period, u64 runtime);

extern void init_entity_runnable_average(struct sched_entity *se);
extern void post_init_entity_util_avg(struct sched_entity *se);

#ifdef CONFIG_NO_HZ_FULL
extern bool sched_can_stop_tick(struct rq *rq);

/*
 * Tick may be needed by tasks in the runqueue depending on their policy and
 * requirements. If tick is needed, lets send the target an IPI to kick it out of
 * nohz mode if necessary.
 */
static inline void sched_update_tick_dependency(struct rq *rq)
{
	int cpu;

	if (!tick_nohz_full_enabled())
		return;

	cpu = cpu_of(rq);

	if (!tick_nohz_full_cpu(cpu))
		return;

	if (sched_can_stop_tick(rq))
		tick_nohz_dep_clear_cpu(cpu, TICK_DEP_BIT_SCHED);
	else
		tick_nohz_dep_set_cpu(cpu, TICK_DEP_BIT_SCHED);
}
#else
static inline void sched_update_tick_dependency(struct rq *rq) { }
#endif

static inline void add_nr_running(struct rq *rq, unsigned count)
{
	unsigned prev_nr = rq->nr_running;

	sched_update_nr_prod(cpu_of(rq), count, true);
	rq->nr_running = prev_nr + count;

	if (prev_nr < 2 && rq->nr_running >= 2) {
#ifdef CONFIG_SMP
		if (!READ_ONCE(rq->rd->overload))
			WRITE_ONCE(rq->rd->overload, 1);
#endif
	}

	sched_update_tick_dependency(rq);
}

static inline void sub_nr_running(struct rq *rq, unsigned count)
{
	sched_update_nr_prod(cpu_of(rq), count, false);
	rq->nr_running -= count;
	/* Check if we still need preemption */
	sched_update_tick_dependency(rq);
}

static inline void rq_last_tick_reset(struct rq *rq)
{
#ifdef CONFIG_NO_HZ_FULL
	rq->last_sched_tick = jiffies;
#endif
}

extern void activate_task(struct rq *rq, struct task_struct *p, int flags);
extern void deactivate_task(struct rq *rq, struct task_struct *p, int flags);

extern void check_preempt_curr(struct rq *rq, struct task_struct *p, int flags);

extern const_debug unsigned int sysctl_sched_time_avg;
extern const_debug unsigned int sysctl_sched_nr_migrate;
extern const_debug unsigned int sysctl_sched_migration_cost;

static inline u64 sched_avg_period(void)
{
	return (u64)sysctl_sched_time_avg * NSEC_PER_MSEC / 2;
}

#ifdef CONFIG_SCHED_HRTICK

/*
 * Use hrtick when:
 *  - enabled by features
 *  - hrtimer is actually high res
 */
static inline int hrtick_enabled(struct rq *rq)
{
	if (!sched_feat(HRTICK))
		return 0;
	if (!cpu_active(cpu_of(rq)))
		return 0;
	return hrtimer_is_hres_active(&rq->hrtick_timer);
}

void hrtick_start(struct rq *rq, u64 delay);

#else

static inline int hrtick_enabled(struct rq *rq)
{
	return 0;
}

#endif /* CONFIG_SCHED_HRTICK */

#ifdef CONFIG_SCHED_WALT
u64 sched_ktime_clock(void);
#else
static inline u64 sched_ktime_clock(void)
{
	return sched_clock();
}
#endif

#ifdef CONFIG_SMP
extern void sched_avg_update(struct rq *rq);
extern unsigned long sched_get_rt_rq_util(int cpu);

#ifndef arch_scale_freq_capacity
static __always_inline
unsigned long arch_scale_freq_capacity(struct sched_domain *sd, int cpu)
{
	return SCHED_CAPACITY_SCALE;
}
#endif

#ifndef arch_scale_max_freq_capacity
static __always_inline
unsigned long arch_scale_max_freq_capacity(struct sched_domain *sd, int cpu)
{
	return SCHED_CAPACITY_SCALE;
}
#endif

#ifndef arch_scale_cpu_capacity
static __always_inline
unsigned long arch_scale_cpu_capacity(struct sched_domain *sd, int cpu)
{
	if (sd && (sd->flags & SD_SHARE_CPUCAPACITY) && (sd->span_weight > 1))
		return sd->smt_gain / sd->span_weight;

	return SCHED_CAPACITY_SCALE;
}
#endif

#ifdef CONFIG_SMP
static inline unsigned long capacity_of(int cpu)
{
	return cpu_rq(cpu)->cpu_capacity;
}

static inline unsigned long capacity_orig_of(int cpu)
{
	return cpu_rq(cpu)->cpu_capacity_orig;
}

extern unsigned int sysctl_sched_use_walt_cpu_util;
extern unsigned int walt_disabled;

static inline unsigned long task_util(struct task_struct *p)
{
#ifdef CONFIG_SCHED_WALT
	if (likely(!walt_disabled && sysctl_sched_use_walt_task_util))
		return p->ravg.demand_scaled;
#endif
	return READ_ONCE(p->se.avg.util_avg);
}

/**
 * Amount of capacity of a CPU that is (estimated to be) used by CFS tasks
 * @cpu: the CPU to get the utilization of
 *
 * The unit of the return value must be the one of capacity so we can compare
 * the utilization with the capacity of the CPU that is available for CFS task
 * (ie cpu_capacity).
 *
 * cfs_rq.avg.util_avg is the sum of running time of runnable tasks plus the
 * recent utilization of currently non-runnable tasks on a CPU. It represents
 * the amount of utilization of a CPU in the range [0..capacity_orig] where
 * capacity_orig is the cpu_capacity available at the highest frequency
 * (arch_scale_freq_capacity()).
 * The utilization of a CPU converges towards a sum equal to or less than the
 * current capacity (capacity_curr <= capacity_orig) of the CPU because it is
 * the running time on this CPU scaled by capacity_curr.
 *
 * The estimated utilization of a CPU is defined to be the maximum between its
 * cfs_rq.avg.util_avg and the sum of the estimated utilization of the tasks
 * currently RUNNABLE on that CPU.
 * This allows to properly represent the expected utilization of a CPU which
 * has just got a big task running since a long sleep period. At the same time
 * however it preserves the benefits of the "blocked utilization" in
 * describing the potential for other tasks waking up on the same CPU.
 *
 * Nevertheless, cfs_rq.avg.util_avg can be higher than capacity_curr or even
 * higher than capacity_orig because of unfortunate rounding in
 * cfs.avg.util_avg or just after migrating tasks and new task wakeups until
 * the average stabilizes with the new running time. We need to check that the
 * utilization stays within the range of [0..capacity_orig] and cap it if
 * necessary. Without utilization capping, a group could be seen as overloaded
 * (CPU0 utilization at 121% + CPU1 utilization at 80%) whereas CPU1 has 20% of
 * available capacity. We allow utilization to overshoot capacity_curr (but not
 * capacity_orig) as it useful for predicting the capacity required after task
 * migrations (scheduler-driven DVFS).
 *
 * Return: the (estimated) utilization for the specified CPU
 */

#ifdef CONFIG_SCHED_WALT
static inline unsigned long cpu_util(int cpu)
#else
static inline unsigned long __cpu_util(int cpu)
#endif
{
	struct cfs_rq *cfs_rq;
	unsigned int util;

#ifdef CONFIG_SCHED_WALT
	if (likely(!walt_disabled && sysctl_sched_use_walt_cpu_util)) {
		u64 walt_cpu_util =
			cpu_rq(cpu)->walt_stats.cumulative_runnable_avg_scaled;

		return min_t(unsigned long, walt_cpu_util,
				capacity_orig_of(cpu));
	}
#endif

	cfs_rq = &cpu_rq(cpu)->cfs;
	util = READ_ONCE(cfs_rq->avg.util_avg);

	if (sched_feat(UTIL_EST))
		util = max(util, READ_ONCE(cfs_rq->avg.util_est.enqueued));

	return min_t(unsigned long, util, capacity_orig_of(cpu));
}

struct sched_walt_cpu_load {
	unsigned long prev_window_util;
	unsigned long nl;
	unsigned long pl;
	u64 ws;
};

static inline unsigned long cpu_util_cum(int cpu, int delta)
{
	u64 util = cpu_rq(cpu)->cfs.avg.util_avg;
	unsigned long capacity = capacity_orig_of(cpu);

#ifdef CONFIG_SCHED_WALT
	if (!walt_disabled && sysctl_sched_use_walt_cpu_util)
		util = cpu_rq(cpu)->cum_window_demand_scaled;
#endif
	delta += util;
	if (delta < 0)
		return 0;

	return (delta >= capacity) ? capacity : delta;
}


#ifdef CONFIG_SCHED_WALT
u64 freq_policy_load(struct rq *rq);

extern u64 walt_load_reported_window;

static inline unsigned long
cpu_util_freq_walt(int cpu, struct sched_walt_cpu_load *walt_load)
{
	u64 util, util_unboosted;
	struct rq *rq = cpu_rq(cpu);
	unsigned long capacity = capacity_orig_of(cpu);
	int boost;

	if (unlikely(walt_disabled || !sysctl_sched_use_walt_cpu_util))
		return cpu_util(cpu);

	boost = per_cpu(sched_load_boost, cpu);
	util_unboosted = util = freq_policy_load(rq);
	util = div64_u64(util * (100 + boost),
			walt_cpu_util_freq_divisor);

	if (walt_load) {
		u64 nl = cpu_rq(cpu)->nt_prev_runnable_sum +
				rq->grp_time.nt_prev_runnable_sum;
		u64 pl = rq->walt_stats.pred_demands_sum_scaled;

		/* do_pl_notif() needs unboosted signals */
		rq->old_busy_time = div64_u64(util_unboosted,
						sched_ravg_window >>
						SCHED_CAPACITY_SHIFT);
		rq->old_estimated_time = pl;

		nl = div64_u64(nl * (100 + boost),
		walt_cpu_util_freq_divisor);

		walt_load->prev_window_util = util;
		walt_load->nl = nl;
		walt_load->pl = pl;
		walt_load->ws = walt_load_reported_window;
	}

	return (util >= capacity) ? capacity : util;
}

static inline unsigned long
cpu_util_freq(int cpu, struct sched_walt_cpu_load *walt_load)
{
	return cpu_util_freq_walt(cpu, walt_load);
}

#else

static inline unsigned long cpu_util_rt(int cpu)
{
	struct rt_rq *rt_rq = &(cpu_rq(cpu)->rt);

	return rt_rq->avg.util_avg;
}

static inline unsigned long cpu_util(int cpu)
{
	return min(__cpu_util(cpu) + cpu_util_rt(cpu), capacity_orig_of(cpu));
}

static inline unsigned long
cpu_util_freq(int cpu, struct sched_walt_cpu_load *walt_load)
{
	return min(cpu_util(cpu), capacity_orig_of(cpu));
}


#define sched_ravg_window TICK_NSEC
#define sysctl_sched_use_walt_cpu_util 0

#endif /* CONFIG_SCHED_WALT */

extern unsigned long
boosted_cpu_util(int cpu, struct sched_walt_cpu_load *walt_load);
extern unsigned int capacity_margin_freq;

static inline unsigned long
add_capacity_margin(unsigned long cpu_capacity, int cpu)
{
	cpu_capacity  = cpu_capacity * capacity_margin_freq *
			(100 + per_cpu(sched_load_boost, cpu));
	cpu_capacity /= 100;
	cpu_capacity /= SCHED_CAPACITY_SCALE;
	return cpu_capacity;
}

#endif /* CONFIG_SMP */

static inline void sched_rt_avg_update(struct rq *rq, u64 rt_delta)
{
	rq->rt_avg += rt_delta * arch_scale_freq_capacity(NULL, cpu_of(rq));
	sched_avg_update(rq);
}
#else
static inline void sched_rt_avg_update(struct rq *rq, u64 rt_delta) { }
static inline void sched_avg_update(struct rq *rq) { }
#endif

#ifdef CONFIG_SMP
#ifdef CONFIG_PREEMPT

static inline void double_rq_lock(struct rq *rq1, struct rq *rq2);

/*
 * fair double_lock_balance: Safely acquires both rq->locks in a fair
 * way at the expense of forcing extra atomic operations in all
 * invocations.  This assures that the double_lock is acquired using the
 * same underlying policy as the spinlock_t on this architecture, which
 * reduces latency compared to the unfair variant below.  However, it
 * also adds more overhead and therefore may reduce throughput.
 */
static inline int _double_lock_balance(struct rq *this_rq, struct rq *busiest)
	__releases(this_rq->lock)
	__acquires(busiest->lock)
	__acquires(this_rq->lock)
{
	raw_spin_unlock(&this_rq->lock);
	double_rq_lock(this_rq, busiest);

	return 1;
}

#else
/*
 * Unfair double_lock_balance: Optimizes throughput at the expense of
 * latency by eliminating extra atomic operations when the locks are
 * already in proper order on entry.  This favors lower cpu-ids and will
 * grant the double lock to lower cpus over higher ids under contention,
 * regardless of entry order into the function.
 */
static inline int _double_lock_balance(struct rq *this_rq, struct rq *busiest)
	__releases(this_rq->lock)
	__acquires(busiest->lock)
	__acquires(this_rq->lock)
{
	int ret = 0;

	if (unlikely(!raw_spin_trylock(&busiest->lock))) {
		if (busiest < this_rq) {
			raw_spin_unlock(&this_rq->lock);
			raw_spin_lock(&busiest->lock);
			raw_spin_lock_nested(&this_rq->lock,
					      SINGLE_DEPTH_NESTING);
			ret = 1;
		} else
			raw_spin_lock_nested(&busiest->lock,
					      SINGLE_DEPTH_NESTING);
	}
	return ret;
}

#endif /* CONFIG_PREEMPT */

/*
 * double_lock_balance - lock the busiest runqueue, this_rq is locked already.
 */
static inline int double_lock_balance(struct rq *this_rq, struct rq *busiest)
{
	if (unlikely(!irqs_disabled())) {
		/* printk() doesn't work good under rq->lock */
		raw_spin_unlock(&this_rq->lock);
		BUG_ON(1);
	}

	return _double_lock_balance(this_rq, busiest);
}

static inline void double_unlock_balance(struct rq *this_rq, struct rq *busiest)
	__releases(busiest->lock)
{
	raw_spin_unlock(&busiest->lock);
	lock_set_subclass(&this_rq->lock.dep_map, 0, _RET_IP_);
}

static inline void double_lock(spinlock_t *l1, spinlock_t *l2)
{
	if (l1 > l2)
		swap(l1, l2);

	spin_lock(l1);
	spin_lock_nested(l2, SINGLE_DEPTH_NESTING);
}

static inline void double_lock_irq(spinlock_t *l1, spinlock_t *l2)
{
	if (l1 > l2)
		swap(l1, l2);

	spin_lock_irq(l1);
	spin_lock_nested(l2, SINGLE_DEPTH_NESTING);
}

static inline void double_raw_lock(raw_spinlock_t *l1, raw_spinlock_t *l2)
{
	if (l1 > l2)
		swap(l1, l2);

	raw_spin_lock(l1);
	raw_spin_lock_nested(l2, SINGLE_DEPTH_NESTING);
}

/*
 * double_rq_lock - safely lock two runqueues
 *
 * Note this does not disable interrupts like task_rq_lock,
 * you need to do so manually before calling.
 */
static inline void double_rq_lock(struct rq *rq1, struct rq *rq2)
	__acquires(rq1->lock)
	__acquires(rq2->lock)
{
	BUG_ON(!irqs_disabled());
	if (rq1 == rq2) {
		raw_spin_lock(&rq1->lock);
		__acquire(rq2->lock);	/* Fake it out ;) */
	} else {
		if (rq1 < rq2) {
			raw_spin_lock(&rq1->lock);
			raw_spin_lock_nested(&rq2->lock, SINGLE_DEPTH_NESTING);
		} else {
			raw_spin_lock(&rq2->lock);
			raw_spin_lock_nested(&rq1->lock, SINGLE_DEPTH_NESTING);
		}
	}
}

/*
 * double_rq_unlock - safely unlock two runqueues
 *
 * Note this does not restore interrupts like task_rq_unlock,
 * you need to do so manually after calling.
 */
static inline void double_rq_unlock(struct rq *rq1, struct rq *rq2)
	__releases(rq1->lock)
	__releases(rq2->lock)
{
	raw_spin_unlock(&rq1->lock);
	if (rq1 != rq2)
		raw_spin_unlock(&rq2->lock);
	else
		__release(rq2->lock);
}

extern void set_rq_online (struct rq *rq);
extern void set_rq_offline(struct rq *rq);
extern bool sched_smp_initialized;

/*
 * task_may_not_preempt - check whether a task may not be preemptible soon
 */
extern bool task_may_not_preempt(struct task_struct *task, int cpu);

#else /* CONFIG_SMP */

/*
 * double_rq_lock - safely lock two runqueues
 *
 * Note this does not disable interrupts like task_rq_lock,
 * you need to do so manually before calling.
 */
static inline void double_rq_lock(struct rq *rq1, struct rq *rq2)
	__acquires(rq1->lock)
	__acquires(rq2->lock)
{
	BUG_ON(!irqs_disabled());
	BUG_ON(rq1 != rq2);
	raw_spin_lock(&rq1->lock);
	__acquire(rq2->lock);	/* Fake it out ;) */
}

/*
 * double_rq_unlock - safely unlock two runqueues
 *
 * Note this does not restore interrupts like task_rq_unlock,
 * you need to do so manually after calling.
 */
static inline void double_rq_unlock(struct rq *rq1, struct rq *rq2)
	__releases(rq1->lock)
	__releases(rq2->lock)
{
	BUG_ON(rq1 != rq2);
	raw_spin_unlock(&rq1->lock);
	__release(rq2->lock);
}

#endif

extern struct sched_entity *__pick_first_entity(struct cfs_rq *cfs_rq);
extern struct sched_entity *__pick_last_entity(struct cfs_rq *cfs_rq);

#ifdef	CONFIG_SCHED_DEBUG
extern bool sched_debug_enabled;

extern void print_cfs_stats(struct seq_file *m, int cpu);
extern void print_rt_stats(struct seq_file *m, int cpu);
extern void print_dl_stats(struct seq_file *m, int cpu);
extern void print_cfs_rq(struct seq_file *m, int cpu, struct cfs_rq *cfs_rq);
extern void print_rt_rq(struct seq_file *m, int cpu, struct rt_rq *rt_rq);
extern void print_dl_rq(struct seq_file *m, int cpu, struct dl_rq *dl_rq);
#ifdef CONFIG_NUMA_BALANCING
extern void
show_numa_stats(struct task_struct *p, struct seq_file *m);
extern void
print_numa_stats(struct seq_file *m, int node, unsigned long tsf,
	unsigned long tpf, unsigned long gsf, unsigned long gpf);
#endif /* CONFIG_NUMA_BALANCING */
#endif /* CONFIG_SCHED_DEBUG */

extern void init_cfs_rq(struct cfs_rq *cfs_rq);
extern void init_rt_rq(struct rt_rq *rt_rq);
extern void init_dl_rq(struct dl_rq *dl_rq);

extern void cfs_bandwidth_usage_inc(void);
extern void cfs_bandwidth_usage_dec(void);

#ifdef CONFIG_NO_HZ_COMMON
enum rq_nohz_flag_bits {
	NOHZ_TICK_STOPPED,
	NOHZ_BALANCE_KICK,
	NOHZ_STATS_KICK
};

#define nohz_flags(cpu)	(&cpu_rq(cpu)->nohz_flags)

extern void nohz_balance_exit_idle(unsigned int cpu);
#else
static inline void nohz_balance_exit_idle(unsigned int cpu) { }
#endif


#ifdef CONFIG_SMP

extern void init_energy_aware_data(int cpu);

static inline
void __dl_update(struct dl_bw *dl_b, s64 bw)
{
	struct root_domain *rd = container_of(dl_b, struct root_domain, dl_bw);
	int i;

	RCU_LOCKDEP_WARN(!rcu_read_lock_sched_held(),
			 "sched RCU must be held");
	for_each_cpu_and(i, rd->span, cpu_active_mask) {
		struct rq *rq = cpu_rq(i);

		rq->dl.extra_bw += bw;
	}
}
#else
static inline
void __dl_update(struct dl_bw *dl_b, s64 bw)
{
	struct dl_rq *dl = container_of(dl_b, struct dl_rq, dl_bw);

	dl->extra_bw += bw;
}
#endif


#ifdef CONFIG_IRQ_TIME_ACCOUNTING
struct irqtime {
	u64			total;
	u64			tick_delta;
	u64			irq_start_time;
	struct u64_stats_sync	sync;
};

DECLARE_PER_CPU(struct irqtime, cpu_irqtime);

/*
 * Returns the irqtime minus the softirq time computed by ksoftirqd.
 * Otherwise ksoftirqd's sum_exec_runtime is substracted its own runtime
 * and never move forward.
 */
static inline u64 irq_time_read(int cpu)
{
	struct irqtime *irqtime = &per_cpu(cpu_irqtime, cpu);
	unsigned int seq;
	u64 total;

	do {
		seq = __u64_stats_fetch_begin(&irqtime->sync);
		total = irqtime->total;
	} while (__u64_stats_fetch_retry(&irqtime->sync, seq));

	return total;
}
#endif /* CONFIG_IRQ_TIME_ACCOUNTING */

#ifdef CONFIG_CPU_FREQ
DECLARE_PER_CPU(struct update_util_data *, cpufreq_update_util_data);

/**
 * cpufreq_update_util - Take a note about CPU utilization changes.
 * @rq: Runqueue to carry out the update for.
 * @flags: Update reason flags.
 *
 * This function is called by the scheduler on the CPU whose utilization is
 * being updated.
 *
 * It can only be called from RCU-sched read-side critical sections.
 *
 * The way cpufreq is currently arranged requires it to evaluate the CPU
 * performance state (frequency/voltage) on a regular basis to prevent it from
 * being stuck in a completely inadequate performance level for too long.
 * That is not guaranteed to happen if the updates are only triggered from CFS
 * and DL, though, because they may not be coming in if only RT tasks are
 * active all the time (or there are RT tasks only).
 *
 * As a workaround for that issue, this function is called periodically by the
 * RT sched class to trigger extra cpufreq updates to prevent it from stalling,
 * but that really is a band-aid.  Going forward it should be replaced with
 * solutions targeted more specifically at RT tasks.
 */
static inline void cpufreq_update_util(struct rq *rq, unsigned int flags)
{
	struct update_util_data *data;
	u64 clock;

#ifdef CONFIG_SCHED_WALT
	if (!(flags & SCHED_CPUFREQ_WALT))
		return;
	clock = sched_ktime_clock();
#else
	clock = rq_clock(rq);
#endif

	data = rcu_dereference_sched(*per_cpu_ptr(&cpufreq_update_util_data,
					cpu_of(rq)));
	if (data)
		data->func(data, clock, flags);
}
#else
static inline void cpufreq_update_util(struct rq *rq, unsigned int flags) {}
#endif /* CONFIG_CPU_FREQ */

#ifdef CONFIG_SCHED_WALT

static inline bool
walt_task_in_cum_window_demand(struct rq *rq, struct task_struct *p)
{
	return cpu_of(rq) == task_cpu(p) &&
	       (p->on_rq || p->last_sleep_ts >= rq->window_start);
}

#endif /* CONFIG_SCHED_WALT */

#ifdef arch_scale_freq_capacity
#ifndef arch_scale_freq_invariant
#define arch_scale_freq_invariant()	(true)
#endif
#else /* arch_scale_freq_capacity */
#define arch_scale_freq_invariant()	(false)
#endif

enum sched_boost_policy {
	SCHED_BOOST_NONE,
	SCHED_BOOST_ON_BIG,
	SCHED_BOOST_ON_ALL,
};

#define NO_BOOST 0
#define FULL_THROTTLE_BOOST 1
#define CONSERVATIVE_BOOST 2
#define RESTRAINED_BOOST 3
#define FULL_THROTTLE_BOOST_DISABLE -1
#define CONSERVATIVE_BOOST_DISABLE -2
#define RESTRAINED_BOOST_DISABLE -3
#define MAX_NUM_BOOST_TYPE (RESTRAINED_BOOST+1)

/*
 * Returns the rq capacity of any rq in a group. This does not play
 * well with groups where rq capacity can change independently.
 */
#define group_rq_capacity(group) cpu_capacity(group_first_cpu(group))

#ifdef CONFIG_SCHED_WALT

static inline int cluster_first_cpu(struct sched_cluster *cluster)
{
	return cpumask_first(&cluster->cpus);
}

struct related_thread_group {
	int id;
	raw_spinlock_t lock;
	struct list_head tasks;
	struct list_head list;
	struct sched_cluster *preferred_cluster;
	struct rcu_head rcu;
	u64 last_update;
};

extern struct list_head cluster_head;
extern struct sched_cluster *sched_cluster[NR_CPUS];

#define for_each_sched_cluster(cluster) \
	list_for_each_entry_rcu(cluster, &cluster_head, list)

#define WINDOW_STATS_RECENT		0
#define WINDOW_STATS_MAX		1
#define WINDOW_STATS_MAX_RECENT_AVG	2
#define WINDOW_STATS_AVG		3
#define WINDOW_STATS_INVALID_POLICY	4

#define SCHED_UPMIGRATE_MIN_NICE 15
#define EXITING_TASK_MARKER	0xdeaddead

#define UP_MIGRATION		1
#define DOWN_MIGRATION		2
#define IRQLOAD_MIGRATION	3

extern struct mutex policy_mutex;
extern unsigned int sched_disable_window_stats;
extern unsigned int max_possible_freq;
extern unsigned int min_max_freq;
extern unsigned int max_possible_efficiency;
extern unsigned int min_possible_efficiency;
extern unsigned int max_capacity;
extern unsigned int min_capacity;
extern unsigned int max_load_scale_factor;
extern unsigned int max_possible_capacity;
extern unsigned int min_max_possible_capacity;
extern unsigned int max_power_cost;
extern unsigned int __read_mostly sched_init_task_load_windows;
extern unsigned int up_down_migrate_scale_factor;
extern unsigned int sysctl_sched_restrict_cluster_spill;
extern unsigned int sched_pred_alert_load;
extern struct sched_cluster init_cluster;
extern unsigned int  __read_mostly sched_short_sleep_task_threshold;
extern unsigned int  __read_mostly sched_long_cpu_selection_threshold;
extern unsigned int  __read_mostly sched_big_waker_task_load;
extern unsigned int  __read_mostly sched_small_wakee_task_load;
extern unsigned int  __read_mostly sched_spill_load;
extern unsigned int  __read_mostly sched_upmigrate;
extern unsigned int  __read_mostly sched_downmigrate;
extern unsigned int  __read_mostly sysctl_sched_spill_nr_run;
extern unsigned int  __read_mostly sched_load_granule;

extern int register_cpu_cycle_counter_cb(struct cpu_cycle_counter_cb *cb);
extern int update_preferred_cluster(struct related_thread_group *grp,
			struct task_struct *p, u32 old_load);
extern void set_preferred_cluster(struct related_thread_group *grp);
extern void add_new_task_to_grp(struct task_struct *new);

static inline int cpu_capacity(int cpu)
{
	return cpu_rq(cpu)->cluster->capacity;
}

static inline int cpu_max_possible_capacity(int cpu)
{
	return cpu_rq(cpu)->cluster->max_possible_capacity;
}

static inline int cpu_load_scale_factor(int cpu)
{
	return cpu_rq(cpu)->cluster->load_scale_factor;
}

static inline int cpu_efficiency(int cpu)
{
	return cpu_rq(cpu)->cluster->efficiency;
}

static inline unsigned int cpu_min_freq(int cpu)
{
	return cpu_rq(cpu)->cluster->min_freq;
}

static inline unsigned int cluster_max_freq(struct sched_cluster *cluster)
{
	/*
	 * Governor and thermal driver don't know the other party's mitigation
	 * voting. So struct cluster saves both and return min() for current
	 * cluster fmax.
	 */
	return min(cluster->max_mitigated_freq, cluster->max_freq);
}

static inline unsigned int cpu_max_freq(int cpu)
{
	return cluster_max_freq(cpu_rq(cpu)->cluster);
}

static inline unsigned int cpu_max_possible_freq(int cpu)
{
	return cpu_rq(cpu)->cluster->max_possible_freq;
}

/* Keep track of max/min capacity possible across CPUs "currently" */
static inline void __update_min_max_capacity(void)
{
	int i;
	int max_cap = 0, min_cap = INT_MAX;

	for_each_possible_cpu(i) {
		if (!cpu_active(i))
			continue;

		max_cap = max(max_cap, cpu_capacity(i));
		min_cap = min(min_cap, cpu_capacity(i));
	}

	max_capacity = max_cap;
	min_capacity = min_cap;
}

/*
 * Return load_scale_factor of a cpu in reference to "most" efficient cpu, so
 * that "most" efficient cpu gets a load_scale_factor of 1
 */
static inline unsigned long
load_scale_cpu_efficiency(struct sched_cluster *cluster)
{
	return DIV_ROUND_UP(1024 * max_possible_efficiency,
			    cluster->efficiency);
}

/*
 * Return load_scale_factor of a cpu in reference to cpu with best max_freq
 * (max_possible_freq), so that one with best max_freq gets a load_scale_factor
 * of 1.
 */
static inline unsigned long load_scale_cpu_freq(struct sched_cluster *cluster)
{
	return DIV_ROUND_UP(1024 * max_possible_freq,
			   cluster_max_freq(cluster));
}

static inline int compute_load_scale_factor(struct sched_cluster *cluster)
{
	int load_scale = 1024;

	/*
	 * load_scale_factor accounts for the fact that task load
	 * is in reference to "best" performing cpu. Task's load will need to be
	 * scaled (up) by a factor to determine suitability to be placed on a
	 * (little) cpu.
	 */
	load_scale *= load_scale_cpu_efficiency(cluster);
	load_scale >>= 10;

	load_scale *= load_scale_cpu_freq(cluster);
	load_scale >>= 10;

	return load_scale;
}

static inline int cpu_max_power_cost(int cpu)
{
	return cpu_rq(cpu)->cluster->max_power_cost;
}

static inline int cpu_min_power_cost(int cpu)
{
	return cpu_rq(cpu)->cluster->min_power_cost;
}

static inline bool hmp_capable(void)
{
	return max_possible_capacity != min_max_possible_capacity;
}

static inline bool is_max_capacity_cpu(int cpu)
{
	return cpu_max_possible_capacity(cpu) == max_possible_capacity;
}

static inline bool is_min_capacity_cpu(int cpu)
{
	return cpu_max_possible_capacity(cpu) == min_max_possible_capacity;
}

/*
 * 'load' is in reference to "best cpu" at its best frequency.
 * Scale that in reference to a given cpu, accounting for how bad it is
 * in reference to "best cpu".
 */
static inline u64 scale_load_to_cpu(u64 task_load, int cpu)
{
	u64 lsf = cpu_load_scale_factor(cpu);

	if (lsf != 1024) {
		task_load *= lsf;
		task_load /= 1024;
	}

	return task_load;
}

/*
 * Return 'capacity' of a cpu in reference to "least" efficient cpu, such that
 * least efficient cpu gets capacity of 1024
 */
static unsigned long
capacity_scale_cpu_efficiency(struct sched_cluster *cluster)
{
	return (1024 * cluster->efficiency) / min_possible_efficiency;
}

/*
 * Return 'capacity' of a cpu in reference to cpu with lowest max_freq
 * (min_max_freq), such that one with lowest max_freq gets capacity of 1024.
 */
static unsigned long capacity_scale_cpu_freq(struct sched_cluster *cluster)
{
	return (1024 * cluster_max_freq(cluster)) / min_max_freq;
}

static inline int compute_capacity(struct sched_cluster *cluster)
{
	int capacity = 1024;

	capacity *= capacity_scale_cpu_efficiency(cluster);
	capacity >>= 10;

	capacity *= capacity_scale_cpu_freq(cluster);
	capacity >>= 10;

	return capacity;
}

static inline unsigned int task_load(struct task_struct *p)
{
	return p->ravg.demand;
}

static inline unsigned int task_pl(struct task_struct *p)
{
	return p->ravg.pred_demand;
}

#define pct_to_real(tunable)	\
		(div64_u64((u64)tunable * (u64)max_task_load(), 100))

#define real_to_pct(tunable)	\
		(div64_u64((u64)tunable * (u64)100, (u64)max_task_load()))

static inline bool task_in_related_thread_group(struct task_struct *p)
{
	return !!(rcu_access_pointer(p->grp) != NULL);
}

static inline
struct related_thread_group *task_related_thread_group(struct task_struct *p)
{
	return rcu_dereference(p->grp);
}

/* Is frequency of two cpus synchronized with each other? */
static inline int same_freq_domain(int src_cpu, int dst_cpu)
{
	struct rq *rq = cpu_rq(src_cpu);

	if (src_cpu == dst_cpu)
		return 1;

	return cpumask_test_cpu(dst_cpu, &rq->freq_domain_cpumask);
}

#define	CPU_RESERVED	1

extern enum sched_boost_policy boost_policy;
static inline enum sched_boost_policy sched_boost_policy(void)
{
	return boost_policy;
}

extern unsigned int sched_boost_type;
static inline int sched_boost(void)
{
	return sched_boost_type;
}

extern int preferred_cluster(struct sched_cluster *cluster,
						struct task_struct *p);
extern struct sched_cluster *rq_cluster(struct rq *rq);
extern void reset_task_stats(struct task_struct *p);
extern void clear_top_tasks_bitmap(unsigned long *bitmap);

#if defined(CONFIG_SCHED_TUNE)
extern bool task_sched_boost(struct task_struct *p);
extern int sync_cgroup_colocation(struct task_struct *p, bool insert);
extern bool schedtune_task_colocated(struct task_struct *p);
extern void update_cgroup_boost_settings(void);
extern void restore_cgroup_boost_settings(void);

#else
static inline bool schedtune_task_colocated(struct task_struct *p)
{
	return false;
}

static inline bool task_sched_boost(struct task_struct *p)
{
	return true;
}

static inline void update_cgroup_boost_settings(void) { }
static inline void restore_cgroup_boost_settings(void) { }
#endif

extern int alloc_related_thread_groups(void);

extern unsigned long all_cluster_ids[];

extern void check_for_migration(struct rq *rq, struct task_struct *p);

static inline int is_reserved(int cpu)
{
	struct rq *rq = cpu_rq(cpu);

	return test_bit(CPU_RESERVED, &rq->walt_flags);
}

static inline int mark_reserved(int cpu)
{
	struct rq *rq = cpu_rq(cpu);

	return test_and_set_bit(CPU_RESERVED, &rq->walt_flags);
}

static inline void clear_reserved(int cpu)
{
	struct rq *rq = cpu_rq(cpu);

	clear_bit(CPU_RESERVED, &rq->walt_flags);
}

static inline bool
task_in_cum_window_demand(struct rq *rq, struct task_struct *p)
{
	return cpu_of(rq) == task_cpu(p) && (p->on_rq || p->last_sleep_ts >=
							 rq->window_start);
}

static inline void walt_fixup_cum_window_demand(struct rq *rq, s64 scaled_delta)
{
	rq->cum_window_demand_scaled += scaled_delta;
	if (unlikely((s64)rq->cum_window_demand_scaled < 0))
		rq->cum_window_demand_scaled = 0;
}

extern void update_cpu_cluster_capacity(const cpumask_t *cpus);

extern unsigned long thermal_cap(int cpu);

extern void clear_walt_request(int cpu);

extern enum sched_boost_policy sched_boost_policy(void);
extern void sched_boost_parse_dt(void);
extern void clear_ed_task(struct task_struct *p, struct rq *rq);
extern bool early_detection_notify(struct rq *rq, u64 wallclock);

static inline unsigned int power_cost(int cpu, u64 demand)
{
	return cpu_max_possible_capacity(cpu);
}

void note_task_waking(struct task_struct *p, u64 wallclock);

static inline bool task_placement_boost_enabled(struct task_struct *p)
{
	if (task_sched_boost(p))
		return sched_boost_policy() != SCHED_BOOST_NONE;

	return false;
}


static inline enum sched_boost_policy task_boost_policy(struct task_struct *p)
{
	enum sched_boost_policy policy = task_sched_boost(p) ?
							sched_boost_policy() :
							SCHED_BOOST_NONE;
	if (policy == SCHED_BOOST_ON_BIG) {
		/*
		 * Filter out tasks less than min task util threshold
		 * under conservative boost.
		 */
		if (sched_boost() == CONSERVATIVE_BOOST &&
				task_util(p) <=
				sysctl_sched_min_task_util_for_boost)
			policy = SCHED_BOOST_NONE;
	}

	return policy;
}

extern void walt_map_freq_to_load(void);
extern void walt_update_min_max_capacity(void);

static inline bool is_min_capacity_cluster(struct sched_cluster *cluster)
{
	return is_min_capacity_cpu(cluster_first_cpu(cluster));
}

#else	/* CONFIG_SCHED_WALT */

struct walt_sched_stats;
struct related_thread_group;
struct sched_cluster;

static inline bool task_sched_boost(struct task_struct *p)
{
	return false;
}

static inline bool task_placement_boost_enabled(struct task_struct *p)
{
	return false;
}

static inline void check_for_migration(struct rq *rq, struct task_struct *p) { }

static inline int sched_boost(void)
{
	return 0;
}

static inline enum sched_boost_policy task_boost_policy(struct task_struct *p)
{
	return SCHED_BOOST_NONE;
}

static inline bool
task_in_cum_window_demand(struct rq *rq, struct task_struct *p)
{
	return false;
}

static inline bool hmp_capable(void) { return false; }
static inline bool is_min_capacity_cpu(int cpu)
{
#ifdef CONFIG_SMP
	int min_cpu = cpu_rq(cpu)->rd->min_cap_orig_cpu;

	return unlikely(min_cpu == -1) ||
		capacity_orig_of(cpu) == capacity_orig_of(min_cpu);
#else
	return true;
#endif
}

#ifdef CONFIG_SMP
static inline int cpu_capacity(int cpu)
{
	return SCHED_CAPACITY_SCALE;
}
#endif

static inline void set_preferred_cluster(struct related_thread_group *grp) { }

static inline bool task_in_related_thread_group(struct task_struct *p)
{
	return false;
}

static inline
struct related_thread_group *task_related_thread_group(struct task_struct *p)
{
	return NULL;
}

static inline u32 task_load(struct task_struct *p) { return 0; }
static inline u32 task_pl(struct task_struct *p) { return 0; }

static inline int update_preferred_cluster(struct related_thread_group *grp,
			 struct task_struct *p, u32 old_load)
{
	return 0;
}

static inline void add_new_task_to_grp(struct task_struct *new) {}

static inline void clear_reserved(int cpu) { }
static inline int alloc_related_thread_groups(void) { return 0; }

#define trace_sched_cpu_load(...)
#define trace_sched_cpu_load_lb(...)
#define trace_sched_cpu_load_cgroup(...)
#define trace_sched_cpu_load_wakeup(...)

static inline void walt_fixup_cum_window_demand(struct rq *rq,
						s64 scaled_delta) { }

static inline void update_cpu_cluster_capacity(const cpumask_t *cpus) { }

#ifdef CONFIG_SMP
static inline unsigned long thermal_cap(int cpu)
{
	return SCHED_CAPACITY_SCALE;
}
#endif

static inline void clear_walt_request(int cpu) { }

static inline int is_reserved(int cpu)
{
	return 0;
}

static inline enum sched_boost_policy sched_boost_policy(void)
{
	return SCHED_BOOST_NONE;
}

static inline void sched_boost_parse_dt(void) { }

static inline void clear_ed_task(struct task_struct *p, struct rq *rq) { }

static inline bool early_detection_notify(struct rq *rq, u64 wallclock)
{
	return 0;
}

static inline void note_task_waking(struct task_struct *p, u64 wallclock) { }
static inline void walt_map_freq_to_load(void) { }
static inline void walt_update_min_max_capacity(void) { }
#endif	/* CONFIG_SCHED_WALT */

struct sched_avg_stats {
	int nr;
	int nr_misfit;
	int nr_max;
};
extern void sched_get_nr_running_avg(struct sched_avg_stats *stats);
