#ifndef KUP_H
#define KUP_H

struct pfn_info {
	unsigned long va;
	unsigned long pfn;
	unsigned long len;
};

struct pidpfns {
	struct list_head proclist;
	unsigned long size; /* total pfns for pid */
	struct pfn_info *pinfo; /* hold pfns */
};

struct saved_pfns {
	spinlock_t lock;
	struct list_head ppfns;
	bool pagesexist;
};

extern struct saved_pfns spfn;

#define KUP_DEBUG_NONE 0 
#define KUP_DEBUG_LOW  1
#define KUP_DEBUG_MID  2
#define KUP_DEBUG_HIGH 3 
#define KUP_DEBUG_LEVEL KUP_DEBUG_NONE

#define kup_log(fmt, ...) 	do {			\
		printk(KERN_ERR "KUP:" fmt , ##__VA_ARGS__);	\
	} while(0)

#define kup_dbg(level, fmt, ...)	do {				\
		 if ((level) >= KUP_DEBUG_LEVEL)			\
			 printk(KERN_ERR "KUP:" fmt , ##__VA_ARGS__);	\
	 } while(0)

#define kup_dbg_pfn_info(__level, __pinfo) do {				\
		kup_dbg(__level,					\
			"%s:%d (va: %lx, pfn: %lx, len: %lu, val: %p)\n", \
			__func__, __LINE__,				\
			(__pinfo)->va,					\
			(__pinfo)->pfn,					\
			(__pinfo)->len,					\
			*((void **)pfn_to_kaddr((__pinfo)->pfn)));	\
	} while(0)
#endif /* KUP_H */
