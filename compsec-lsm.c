

/*
 *  Copyright (C) 2024 Emily Dror <emily.d@campus.technion.ac.il>
 *      Exercise 3 - Technion CS 236652 Computer Security
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License version 2,
 *	as published by the Free Software Foundation.
 *
 *  Author:
 *          Emily Dror <emily.d@campus.technion.ac.il>
 */

#include <linux/init.h>
#include <linux/kd.h>
#include <linux/kernel.h>
#include <linux/tracehook.h>
#include <linux/errno.h>
#include <linux/ext2_fs.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/xattr.h>
#include <linux/capability.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/proc_fs.h>
#include <linux/swap.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/tty.h>
#include <net/icmp.h>
#include <net/ip.h>		/* for local_port_range[] */
#include <net/tcp.h>		/* struct or_callable used in sock_rcv_skb */
#include <net/inet_connection_sock.h>
#include <net/net_namespace.h>
#include <net/netlabel.h>
#include <linux/uaccess.h>
#include <asm/ioctls.h>
#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>	/* for network interface checks */
#include <linux/netlink.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/dccp.h>
#include <linux/quota.h>
#include <linux/un.h>		/* for Unix socket types */
#include <net/af_unix.h>	/* for Unix socket types */
#include <linux/parser.h>
#include <linux/nfs_mount.h>
#include <net/ipv6.h>
#include <linux/hugetlb.h>
#include <linux/personality.h>
#include <linux/audit.h>
#include <linux/string.h>
#include <linux/selinux.h>
#include <linux/mutex.h>
#include <linux/posix-timers.h>
#include <linux/syslog.h>
#include <linux/user_namespace.h>
#include <linux/export.h>

extern struct security_operations *security_ops;

#ifdef CONFIG_SECURITY_COMPSEC

#define COMPSEC_LOG "compsec: "


/* Task compsec data. */
struct task_blob {
	unsigned int proc_class; /* classification */
};


/* Allocate compsec blob and store them in task's credentials. */
static int compsec_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
    struct task_blob *blob = kzalloc(sizeof(*blob), gfp);
    if (!blob) {
        cred->security = NULL;
        return -ENOMEM;
    }
    cred->security = blob;
    return 0;
}


/* Free compsec blob in task's credentials. */
static void compsec_cred_free(struct cred *cred)
{
    if (cred->security) {
        kfree(cred->security);
    }
    cred->security = NULL;
}


/* Set creds for exec according to binary's EA. */
static int compsec_bprm_set_creds(struct linux_binprm *bprm)
{
    // Get bin's class
	unsigned int bin_class;
    struct dentry *dp = bprm->file->f_path.dentry;
    if (vfs_getxattr(dp, "security.compsec", &bin_class, sizeof(unsigned int)) < 0) {
        bin_class = 0;
    }

    // Set process's class = bin's class
	struct task_blob *blob = bprm->cred->security;
    if (!blob) {
        return -ENOMEM;
    }
    blob->proc_class = bin_class;
    return 0;
}


/* Prepare creds from old task to a new one. */
static int compsec_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp)
{
    if (!old || !new) {
        return 0;
    }

    struct task_blob *new_blob;
    const struct task_blob *old_blob = old->security;
    if (!old_blob) {
        new_blob = kzalloc(sizeof(*new_blob), gfp);
    } else {
        new_blob = kmemdup(old_blob, sizeof(*new_blob), gfp);
    }

    if (!new_blob) {
        return -ENOMEM;
    }
    if (!old_blob) {
        new_blob->proc_class = 0;
    }
    new->security = new_blob;
	return 0;
}


/* Transfer creds from old task to a new one. */
static void compsec_cred_transfer(struct cred *new, const struct cred *old)
{
    if (!old || !new) {
        return;
    }
    *(struct task_blob *)(new->security) = *(struct task_blob *)(old->security);
}


/* Check File permissions. */
static int compsec_file_permission(struct file *file, int mask)
{
    // Get target file's dentry
    struct dentry *dp = file->f_path.dentry;
    if(dp->d_inode->i_rdev) {
        // We are not enforcing on char/block devices
        return 0;
    }

    // Allow init process to access all files
    if (current->pid == 1) {
        return 0;
    }

    // Get target file's class
	unsigned int file_class;
    if (vfs_getxattr(dp, "security.compsec", &file_class, sizeof(unsigned int)) < 0) {
        file_class = 0;
    }

    // Get current task's blob
    struct task_blob *blob = current_cred()->security;
    if (!blob) {
        printk(COMPSEC_LOG  "Access granted for process (%d) "
                            "due to lack of memory.\n", current->pid);
        return 0;
    }

    // Implement read down policy of according to Bel-LaPadula module
    if (mask & MAY_READ) {
        if (file_class <= blob->proc_class) {
            return 0;
        }
        printk(COMPSEC_LOG  "Read access refused for process (%d) "
                            "due to Bel-LaPadula module. "
                            "file's class %u > process's class %u.\n",
                            current->pid, file_class, blob->proc_class);
    }

    // Implement write up policy of according to Bel-LaPadula module
    if (mask & MAY_WRITE) {
        if (file_class >= blob->proc_class) {
            return 0;
        }
        printk(COMPSEC_LOG  "Write access refused for process (%d) "
                            "due to Bel-LaPadula module. "
                            "file's class %u < process's class %u.\n",
                            current->pid, file_class, blob->proc_class);
    }

    return -EACCES;
}


/* Set security operations. */
static struct security_operations compsec_ops = {
  .name             = "compsec",
  .bprm_set_creds   = compsec_bprm_set_creds,
  .file_permission  = compsec_file_permission,
  .cred_alloc_blank = compsec_cred_alloc_blank,
  .cred_free        = compsec_cred_free,
  .cred_prepare     = compsec_cred_prepare,
  .cred_transfer    = compsec_cred_transfer,
};


/* Load and unload module. */
static __init int compsec_init(void)
{
    if (!security_module_enable(&compsec_ops)) {
        printk(COMPSEC_LOG "Disabled at boot.\n");
        return 0;
    }

    if (register_security(&compsec_ops)) {
        panic(COMPSEC_LOG "Unable to register compsec with kernel.\n");
    } else {
        printk(COMPSEC_LOG "Registered with the kernel\n");
    }
    return 0;
}

static void __exit compsec_exit(void) {}

module_init (compsec_init);
module_exit (compsec_exit);

#endif  // CONFIG_SECURITY_compsec
