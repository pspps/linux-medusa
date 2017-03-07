#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/tracehook.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/xattr.h>
#include <linux/capability.h>
#include <linux/unistd.h>
#include <linux/lsm_hooks.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/proc_fs.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/tty.h>
#include <net/icmp.h>
#include <net/ip.h> /* for local_port_range[] */
#include <net/tcp.h> /* struct or_callable used in sock_rcv_skb */
#include <net/net_namespace.h>
#include <net/netlabel.h>
#include <linux/uaccess.h>
#include <asm/ioctls.h>
#include <asm/atomic.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h> /* for network interface checks */
#include <linux/netlink.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/dccp.h>
#include <linux/quota.h>
#include <linux/un.h> /* for Unix socket types */
#include <net/af_unix.h> /* for Unix socket types */
#include <linux/parser.h>
#include <linux/nfs_mount.h>
#include <net/ipv6.h>
#include <linux/hugetlb.h>
#include <linux/personality.h>
#include <linux/sysctl.h>
#include <linux/audit.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/posix-timers.h>
#include <linux/cred.h>
#include <linux/medusa/l3/registry.h>
#include <linux/medusa/l1/inode.h> 
#include <linux/medusa/l4/comm.h>
#include <linux/medusa/l1/file_handlers.h>
#include <linux/medusa/l1/task.h>
#include <linux/medusa/l1/process_handlers.h>
#include "../l2/kobject_process.h"
#include "../l2/kobject_file.h"
#include "../l0/init_medusa.h"

#ifdef CONFIG_SECURITY_MEDUSA

int medusa_l1_cred_alloc_blank(struct cred *cred, gfp_t gfp);
int medusa_l1_inode_alloc_security(struct inode *inode);


static int medusa_l1_bprm_check_security (struct linux_binprm *bprm)
{
	return 0;
}

static void medusa_l1_bprm_committing_creds(struct linux_binprm *bprm)
{
}

static void medusa_l1_bprm_committed_creds(struct linux_binprm *bprm)
{
}

static int medusa_l1_sb_alloc_security(struct super_block *sb)
{
	return 0;
}

static void medusa_l1_sb_free_security(struct super_block *sb)
{
}

static int medusa_l1_sb_copy_data(char *orig, char *copy)
{
	return 0;
}

static int medusa_l1_sb_remount(struct super_block *sb, void *data)
{
	return 0;
} 

static int medusa_l1_sb_kern_mount(struct super_block *sb, int flags, void *data)
{
	struct dentry *root = sb->s_root;
	struct inode *inode = root->d_inode;

	if (&inode_security(inode) == NULL)
		medusa_l1_inode_alloc_security(inode);

	return 0;
}

static int medusa_l1_sb_show_options(struct seq_file *m, struct super_block *sb)
{
	return 0;
}

static int medusa_l1_sb_statfs(struct dentry *dentry)
{
	return 0;
}

static int medusa_l1_sb_mount(const char *dev_name, const struct path *path, const char *type,
			unsigned long flags, void *data)
{
	return 0;
}

static int medusa_l1_sb_umount(struct vfsmount *mnt, int flags)
{
	return 0;
}


static int medusa_l1_sb_pivotroot(const struct path *old_path, const struct path *new_path)
{
	return 0;
}

static int medusa_l1_sb_set_mnt_opts(struct super_block *sb,
				struct security_mnt_opts *opts,
								unsigned long kern_flags,
								unsigned long *set_kern_flags)
{
	if (unlikely(opts->num_mnt_opts))
		return -EOPNOTSUPP;
	return 0;
}

static int medusa_l1_sb_clone_mnt_opts(const struct super_block *oldsb,
				struct super_block *newsb)
{
	return 0;
}

static int medusa_l1_sb_parse_opts_str(char *options, struct security_mnt_opts *opts)
{
	return 0;
}

static int medusa_l1_dentry_init_security(struct dentry *dentry, int mode, 
					const struct qstr *name, void **ctx, u32 *ctxlen)
{
	if (dentry->d_inode != NULL) {
		if (&inode_security(dentry->d_inode) == NULL)
			medusa_l1_inode_alloc_security(dentry->d_inode);

	}
	return -EOPNOTSUPP;
}

int medusa_l1_inode_alloc_security(struct inode *inode)
{
	struct medusa_l1_inode_s *med;

	med = (struct medusa_l1_inode_s*) kmalloc(sizeof(struct medusa_l1_inode_s), GFP_KERNEL);

	if (med == NULL)
		return -ENOMEM;

	inode->i_security = med;
	medusa_clean_inode(inode);

	return 0;
}

void medusa_l1_inode_free_security(struct inode *inode)
{
		struct medusa_l1_inode_s *med;

	if (inode->i_security != NULL) {
		med = inode->i_security;
		inode->i_security = NULL;
		kfree(med);
	}
}

static int medusa_l1_inode_init_security(struct inode *inode, struct inode *dir,
									const struct qstr *qstr, const char **name,
									void **value, size_t *len)
{
	medusa_clean_inode(inode);

	return 0;
}

static int medusa_l1_inode_create(struct inode *inode, struct dentry *dentry,
				umode_t mode)
{
	if (medusa_create(dentry, mode) == MED_NO)
		return -EACCES;

	return 0;
}

static int medusa_l1_inode_link(struct dentry *old_dentry, struct inode *inode,
			struct dentry *new_dentry)
{
	if (medusa_link(old_dentry, new_dentry->d_name.name) == MED_NO)
		return -EPERM;

	return 0;
}

static int medusa_l1_inode_unlink(struct inode *inode, struct dentry *dentry)
{
	if (medusa_unlink(dentry) == MED_NO)
		return -EPERM;
	return 0;
}

static int medusa_l1_inode_symlink(struct inode *inode, struct dentry *dentry,
				 const char *name)
{
	if (medusa_symlink(dentry, name) == MED_NO)
		return -EPERM;
	
	return 0;
}

static int medusa_l1_inode_mkdir(struct inode *inode, struct dentry *dentry,
				umode_t mask)
{
	if(medusa_mkdir(dentry, mask) == MED_NO)
		return -EPERM;
	return 0;
}

static int medusa_l1_inode_rmdir(struct inode *inode, struct dentry *dentry)
{
	if (medusa_rmdir(dentry) == MED_NO)
		return -EPERM;
	return 0;
}

static int medusa_l1_inode_mknod(struct inode *inode, struct dentry *dentry,
			umode_t mode, dev_t dev)
{
	if(medusa_mknod(dentry, dev, mode) == MED_NO)
		return -EPERM;
	return 0;
}

static int medusa_l1_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
				struct inode *new_inode, struct dentry *new_dentry)
{
	if (medusa_rename(old_dentry, new_dentry->d_name.name) == MED_NO)
		return -EPERM;
	return 0;
}

static int medusa_l1_inode_readlink(struct dentry *dentry)
{
	if (medusa_readlink(dentry) == MED_NO)
		return -EPERM;
	return 0;
}

static int medusa_l1_inode_follow_link(struct dentry *dentry, struct inode* inode,
				 bool rcu)
{
	return 0;
}

static int medusa_l1_inode_permission(struct inode *inode, int mask)
{
	return 0;
}

static int medusa_l1_inode_setattr(struct dentry *dentry, struct iattr *iattr)
{
	return 0;
}

static int medusa_l1_inode_getattr(const struct path* path)
{
	return 0;
}

static void medusa_l1_inode_post_setxattr(struct dentry *dentry, const char *name,
					const void *value, size_t size, int flags)
{
}

static int medusa_l1_inode_getxattr(struct dentry *dentry, const char *name)
{
	return 0;
}

static int medusa_l1_inode_listxattr(struct dentry *dentry)
{
	return 0;
}

static int medusa_l1_inode_getsecurity(struct inode *inode, const char *name,
				 void **buffer, bool alloc)
{
	return -EOPNOTSUPP;
	return 0;
}

static int medusa_l1_inode_setsecurity(struct inode *inode, const char *name,
				 const void *value, size_t size, int flags)
{
	return -EOPNOTSUPP;
	return 0;
}

static int medusa_l1_inode_listsecurity(struct inode *inode, char *buffer,
				size_t buffer_size)
{
	return 0;
}

static void medusa_l1_inode_getsecid(struct inode *inode, u32 *secid)
{
	*secid = 0;
}

#ifdef CONFIG_SECURITY_PATH
static int medusa_l1_path_mknod(const struct path *dir, struct dentry *dentry, umode_t mode,
				unsigned int dev)
{
	return 0;
}

static int medusa_l1_path_mkdir(const struct path *dir, struct dentry *dentry, umode_t mode)
{
	return 0;
}

static int medusa_l1_path_rmdir(const struct path *dir, struct dentry *dentry)
{
	return 0;
}

static int medusa_l1_path_unlink(const struct path *dir, struct dentry *dentry)
{
	return 0;
}

static int medusa_l1_path_symlink(const struct path *dir, struct dentry *dentry,
				const char *old_name)
{
	return 0;
}

static int medusa_l1_path_link(struct dentry *old_dentry, const struct path *new_dir,
			 struct dentry *new_dentry)
{
	return 0;
}

static int medusa_l1_path_rename(const struct path *old_path, struct dentry *old_dentry,
			const struct path *new_path, struct dentry *new_dentry)
{
	return 0;
}

static int medusa_l1_path_truncate(const struct path *path)
{
	return 0;
}

static int medusa_l1_path_chmod(const struct path *path, umode_t mode)
{
	return 0;
}

static int medusa_l1_path_chown(const struct path *path, kuid_t uid, kgid_t gid)
{
	return 0;
}

static int medusa_l1_path_chroot(const struct path *root)
{
	return 0;
}
#endif

static int medusa_l1_file_permission(struct file *file, int mask)
{
	//printk("medusa: file_permission called\n");
	return 0;
}

static int medusa_l1_file_alloc_security(struct file *file)
{
	return 0;
}

static void medusa_l1_file_free_security(struct file *file)
{
}

static int medusa_l1_file_ioctl(struct file *file, unsigned int command,
			unsigned long arg)
{
	return 0;
}

static int medusa_l1_file_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
				 unsigned long prot)
{
	return 0;
}

static int medusa_l1_file_lock(struct file *file, unsigned int cmd)
{
	return 0;
}

static int medusa_l1_file_fcntl(struct file *file, unsigned int cmd,
			unsigned long arg)
{
	return 0;
}

static void medusa_l1_file_set_fowner(struct file *file)
{
	return;
}

static int medusa_l1_file_send_sigiotask(struct task_struct *tsk,
				struct fown_struct *fown, int sig)
{
	return 0;
}

static int medusa_l1_file_receive(struct file *file)
{
	return 0;
}

//static int medusa_l1_dentry_open(struct file *file, const struct cred *cred)
//{
//	return 0;
//}

static int medusa_l1_task_create(unsigned long clone_flags)
{
        if(medusa_fork(clone_flags) == MED_NO)
                return -EPERM;   
	return 0;
}

static void medusa_l1_task_free(struct task_struct *task)
{
}

int medusa_l1_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	struct medusa_l1_task_s* med;
	struct cred* tmp;

	printk("medusa: init security: %s task\n", current->comm);
	
	med = (struct medusa_l1_task_s*) kmalloc(sizeof(struct medusa_l1_task_s), gfp);
	
	if (med == NULL)
			return -ENOMEM;
	
	cred->security = med;

	tmp = (struct cred*) current->cred;
	current->cred = cred;

	medusa_init_process(current);
	current->cred = tmp;
	
	return 0;
}

void medusa_l1_cred_free(struct cred *cred)
{
	if (cred->security)
		kfree(cred->security);

	cred->security = NULL;
}

static int medusa_l1_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp)
{
	struct medusa_l1_task_s* med;
	
	if (old->security == NULL || new->security != NULL) {
		return 0;
	}
		
	med = (struct medusa_l1_task_s*) kmalloc(sizeof(struct medusa_l1_task_s), gfp);

	if (med == NULL) {
			return -ENOMEM;
	}

	memcpy(med, old->security, sizeof(struct medusa_l1_task_s));

	new->security = med;
	
	return 0;
}

static void medusa_l1_cred_transfer(struct cred *new, const struct cred *old)
{
	//medusa_l1_cred_prepare(new, old, GFP_KERNEL);
	//medusa_l1_cred_alloc_blank(new, GFP_KERNEL);
	return;
}

static int medusa_l1_kernel_act_as(struct cred *new, u32 secid)
{
	return 0;
}

static int medusa_l1_kernel_create_files_as(struct cred *new, struct inode *inode)
{
	return 0;
}

static int medusa_l1_kernel_module_request(char *kmod_name)
{
	return 0;
}

static int medusa_l1_kernel_module_from_file(struct file *file)
{
	return 0;
}

static int medusa_l1_task_fix_setuid(struct cred *new, const struct cred *old,
								int flags)
{
	return cap_task_fix_setuid(new, old, flags);
}

static int medusa_l1_task_setpgid(struct task_struct *p, pid_t pgid)
{
	return 0;
}

static int medusa_l1_task_getpgid(struct task_struct *p)
{
	return 0;
}

static int medusa_l1_task_getsid(struct task_struct *p)
{
	return 0;
}

static void medusa_l1_task_getsecid(struct task_struct *p, u32 *secid)
{
	*secid = 0;
}

static int medusa_l1_task_getioprio(struct task_struct *p)
{
	return 0;
}

static int medusa_l1_task_setrlimit(struct task_struct *p, unsigned int resource,
				 struct rlimit *new_rlim)
{
	return 0;
}

static int medusa_l1_task_getscheduler(struct task_struct *p)
{
	return 0;
}

static int medusa_l1_task_movememory(struct task_struct *p)
{
	return 0;
}

static int medusa_l1_task_wait(struct task_struct *p)
{
	return 0;
}

static int medusa_l1_task_kill(struct task_struct *p, struct siginfo *info,
			 int sig, u32 secid)
{
    if(medusa_sendsig(sig, info, p) == MED_NO)
		return -EPERM;
	return 0;
}

static void medusa_l1_task_to_inode(struct task_struct *p, struct inode *inode)
{
}

static void medusa_l1_d_instantiate(struct dentry *dentry, struct inode *inode)
{
}

static int medusa_l1_getprocattr(struct task_struct *p, char *name, char **value)
{
	return -EINVAL;
}

static int medusa_l1_setprocattr(struct task_struct *p, char *name, void *value,
			size_t size)
{
	return -EINVAL;
}

static int medusa_l1_inode_notifysecctx(struct inode *inode, void *ctx, u32 ctxlen)
{
	return -EOPNOTSUPP;
}

static int medusa_l1_inode_setsecctx(struct dentry *dentry, void *ctx, u32 ctxlen)
{
	return -EOPNOTSUPP;
}

static int medusa_l1_inode_getsecctx(struct inode *inode, void **ctx, u32 *ctxlen)
{
	return -EOPNOTSUPP;
}

static int medusa_l1_bprm_set_creds(struct linux_binprm *bprm)
{
	return 0;
//	struct inode* inode = file_inode(bprm->file);
//	if (!work)
//		return 0;
//#ifdef CONFIG_MEDUSA_FILE_CAPABILITIES
//	if (MED_MAGIC_VALID(&inode_security(inode)) ||
//			file_kobj_validate_dentry(bprm->file->f_dentry,NULL) > 0) {
//		/* If the security daemon sets the file capabilities, use them */
//		bprm->cred->cap_inheritable = inode_security(inode).icap;
//		bprm->cred->cap_permitted = inode_security(inode).pcap;
//		bprm->cred->cap_effective = inode_security(inode).ecap;
//	}
//#endif /* CONFIG_MEDUSA_FILE_CAPABILITIES */
//
//	{
//		int retval;
//#ifndef CONFIG_MEDUSA_FILE_CAPABILITIES
//		kernel_cap_t new_permitted, working;
//
///* Privilege elevation check copied from compute_creds() */
//		new_permitted = cap_intersect(bprm->cap_permitted, cap_bset);
//		working = cap_intersect(bprm->cap_inheritable,
//					current->cap_inheritable);
//		new_permitted = cap_combine(new_permitted, working);
//#endif
//		if (!uid_eq(bprm->cred->euid,task_uid(current)) || !gid_eq(bprm->cred->egid, task_gid(current))
//#ifndef CONFIG_MEDUSA_FILE_CAPABILITIES
//			|| !cap_issubset(new_permitted, current->cap_permitted)
//#endif
//		) {
//			if ((retval = medusa_sexec(bprm)) == MED_NO)
//				return -EPERM;
//			if (retval == MED_SKIP) {
//				bprm->cred->euid = task_euid(current);
//				bprm->cred->egid = task_egid(current);
//#ifndef CONFIG_MEDUSA_FILE_CAPABILITIES
//				cap_clear(bprm->cap_inheritable);
//				bprm->cap_permitted = current->cap_permitted;
//				bprm->cap_effective = current->cap_effective;
//#endif
//			}
//		}
//	}
//	return 0;
}

static int medusa_l1_bprm_secureexec(struct linux_binprm *bprm)
{
	return 0;
	if (medusa_sexec(bprm) == MED_NO)
		return -EPERM;

	return 0;
}
	

static int medusa_l1_inode_setxattr(struct dentry *dentry, const char *name,
					const void *value, size_t size, int flags)
{
	return cap_inode_setxattr(dentry, name, value, size, flags);
} 


static int medusa_l1_inode_removexattr(struct dentry *dentry, const char *name)
{
	return cap_inode_removexattr(dentry, name);
} 

static int medusa_l1_inode_need_killpriv(struct dentry *dentry) 
{
	return cap_inode_need_killpriv(dentry);
}

static int medusa_l1_inode_killpriv(struct dentry *dentry)
{
	return cap_inode_killpriv(dentry);
}

static int medusa_l1_mmap_addr(unsigned long addr) 
{
	return cap_mmap_addr(addr);
}

static int medusa_l1_mmap_file(struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags)
{
	//printk("medusa: file_mmap called\n");
	return 0;
} 


static int medusa_l1_task_setnice(struct task_struct *p, int nice)
{
	return cap_task_setnice(p, nice);
} 


static int medusa_l1_task_setioprio(struct task_struct *p, int ioprio)
{
	return cap_task_setioprio(p, ioprio);
} 



static int medusa_l1_task_setscheduler(struct task_struct *p)
{
	return cap_task_setscheduler(p);
} 


static int medusa_l1_task_prctl(int option, unsigned long arg2,
						unsigned long arg3, unsigned long arg4,
						unsigned long arg5)
{
	return cap_task_prctl(option, arg2, arg3, arg4, arg5);
}


static struct security_hook_list medusa_l1_hooks[] = {
	LSM_HOOK_INIT(bprm_set_creds, medusa_l1_bprm_set_creds),
	LSM_HOOK_INIT(bprm_check_security, medusa_l1_bprm_check_security),
	LSM_HOOK_INIT(bprm_secureexec, medusa_l1_bprm_secureexec),
	LSM_HOOK_INIT(bprm_committing_creds, medusa_l1_bprm_committing_creds),
	LSM_HOOK_INIT(bprm_committed_creds, medusa_l1_bprm_committed_creds),

	LSM_HOOK_INIT(sb_alloc_security, medusa_l1_sb_alloc_security),
	LSM_HOOK_INIT(sb_free_security, medusa_l1_sb_free_security),
	LSM_HOOK_INIT(sb_copy_data, medusa_l1_sb_copy_data),
	LSM_HOOK_INIT(sb_remount, medusa_l1_sb_remount),
	LSM_HOOK_INIT(sb_kern_mount, medusa_l1_sb_kern_mount),
	LSM_HOOK_INIT(sb_show_options, medusa_l1_sb_show_options),
	LSM_HOOK_INIT(sb_statfs, medusa_l1_sb_statfs),
	LSM_HOOK_INIT(sb_mount, medusa_l1_sb_mount),
	LSM_HOOK_INIT(sb_umount, medusa_l1_sb_umount),
	LSM_HOOK_INIT(sb_pivotroot, medusa_l1_sb_pivotroot),
	LSM_HOOK_INIT(sb_set_mnt_opts, medusa_l1_sb_set_mnt_opts),
	LSM_HOOK_INIT(sb_clone_mnt_opts, medusa_l1_sb_clone_mnt_opts),
	LSM_HOOK_INIT(sb_parse_opts_str, medusa_l1_sb_parse_opts_str),
	LSM_HOOK_INIT(dentry_init_security, medusa_l1_dentry_init_security),

#ifdef CONFIG_SECURITY_PATH
		LSM_HOOK_INIT(path_unlink, medusa_l1_path_unlink),
		LSM_HOOK_INIT(path_mkdir, medusa_l1_path_mkdir),
		LSM_HOOK_INIT(path_rmdir, medusa_l1_path_rmdir),
		LSM_HOOK_INIT(path_mknod, medusa_l1_path_mknod),
		LSM_HOOK_INIT(path_truncate, medusa_l1_path_truncate),
		LSM_HOOK_INIT(path_symlink, medusa_l1_path_symlink),
		LSM_HOOK_INIT(path_link, medusa_l1_path_link),
		LSM_HOOK_INIT(path_rename, medusa_l1_path_rename),
		LSM_HOOK_INIT(path_chmod, medusa_l1_path_chmod),
		LSM_HOOK_INIT(path_chown, medusa_l1_path_chown),
		LSM_HOOK_INIT(path_chroot, medusa_l1_path_chroot),
#endif

	// LSM_HOOK_INIT(inode_alloc_security, medusa_l1_inode_alloc_security),
	// LSM_HOOK_INIT(inode_free_security, medusa_l1_inode_free_security),
	LSM_HOOK_INIT(inode_init_security, medusa_l1_inode_init_security),
	LSM_HOOK_INIT(inode_create, medusa_l1_inode_create),
	LSM_HOOK_INIT(inode_link, medusa_l1_inode_link),
	LSM_HOOK_INIT(inode_unlink, medusa_l1_inode_unlink),
	LSM_HOOK_INIT(inode_symlink, medusa_l1_inode_symlink),
	LSM_HOOK_INIT(inode_mkdir, medusa_l1_inode_mkdir),
	LSM_HOOK_INIT(inode_rmdir, medusa_l1_inode_rmdir),
	LSM_HOOK_INIT(inode_mknod, medusa_l1_inode_mknod),
	LSM_HOOK_INIT(inode_rename, medusa_l1_inode_rename),
	LSM_HOOK_INIT(inode_readlink, medusa_l1_inode_readlink),
	LSM_HOOK_INIT(inode_follow_link, medusa_l1_inode_follow_link),
	LSM_HOOK_INIT(inode_permission, medusa_l1_inode_permission),
	LSM_HOOK_INIT(inode_setattr, medusa_l1_inode_setattr),
	LSM_HOOK_INIT(inode_getattr, medusa_l1_inode_getattr),
	LSM_HOOK_INIT(inode_setxattr, medusa_l1_inode_setxattr),
	LSM_HOOK_INIT(inode_post_setxattr, medusa_l1_inode_post_setxattr),
	LSM_HOOK_INIT(inode_getxattr, medusa_l1_inode_getxattr),
	LSM_HOOK_INIT(inode_listxattr, medusa_l1_inode_listxattr),
	LSM_HOOK_INIT(inode_removexattr, medusa_l1_inode_removexattr),
	LSM_HOOK_INIT(inode_need_killpriv, medusa_l1_inode_need_killpriv),
	LSM_HOOK_INIT(inode_killpriv, medusa_l1_inode_killpriv),
	LSM_HOOK_INIT(inode_getsecurity, medusa_l1_inode_getsecurity),
	LSM_HOOK_INIT(inode_setsecurity, medusa_l1_inode_setsecurity),
	LSM_HOOK_INIT(inode_listsecurity, medusa_l1_inode_listsecurity),
	LSM_HOOK_INIT(inode_getsecid, medusa_l1_inode_getsecid),

	LSM_HOOK_INIT(file_permission, medusa_l1_file_permission),
	LSM_HOOK_INIT(file_alloc_security, medusa_l1_file_alloc_security),
	LSM_HOOK_INIT(file_free_security, medusa_l1_file_free_security),
	LSM_HOOK_INIT(file_ioctl, medusa_l1_file_ioctl),
	LSM_HOOK_INIT(mmap_addr, medusa_l1_mmap_addr),
	LSM_HOOK_INIT(mmap_file, medusa_l1_mmap_file),
	LSM_HOOK_INIT(file_mprotect, medusa_l1_file_mprotect),
	LSM_HOOK_INIT(file_lock, medusa_l1_file_lock),
	LSM_HOOK_INIT(file_fcntl, medusa_l1_file_fcntl),
	LSM_HOOK_INIT(file_set_fowner, medusa_l1_file_set_fowner),
	LSM_HOOK_INIT(file_send_sigiotask, medusa_l1_file_send_sigiotask),
	LSM_HOOK_INIT(file_receive, medusa_l1_file_receive),

	//LSM_HOOK_INIT(dentry_open, medusa_l1_dentry_open),

	LSM_HOOK_INIT(task_create, medusa_l1_task_create),
	LSM_HOOK_INIT(task_free, medusa_l1_task_free),
	// LSM_HOOK_INIT(cred_alloc_blank, medusa_l1_cred_alloc_blank),
	// LSM_HOOK_INIT(cred_free, medusa_l1_cred_free),
	LSM_HOOK_INIT(cred_prepare, medusa_l1_cred_prepare),
	LSM_HOOK_INIT(cred_transfer, medusa_l1_cred_transfer),
	LSM_HOOK_INIT(kernel_act_as, medusa_l1_kernel_act_as),
	LSM_HOOK_INIT(kernel_create_files_as, medusa_l1_kernel_create_files_as),
	LSM_HOOK_INIT(kernel_module_request, medusa_l1_kernel_module_request),
	//LSM_HOOK_INIT(kernel_module_from_file, medusa_l1_kernel_module_from_file),
	LSM_HOOK_INIT(task_fix_setuid, medusa_l1_task_fix_setuid),
	LSM_HOOK_INIT(task_setpgid, medusa_l1_task_setpgid),
	LSM_HOOK_INIT(task_getpgid, medusa_l1_task_getpgid),
	LSM_HOOK_INIT(task_getsid, medusa_l1_task_getsid),
	LSM_HOOK_INIT(task_getsecid, medusa_l1_task_getsecid),
	LSM_HOOK_INIT(task_setnice, medusa_l1_task_setnice),
	LSM_HOOK_INIT(task_setioprio, medusa_l1_task_setioprio),
	LSM_HOOK_INIT(task_getioprio, medusa_l1_task_getioprio),
	LSM_HOOK_INIT(task_setrlimit, medusa_l1_task_setrlimit),
	LSM_HOOK_INIT(task_setscheduler, medusa_l1_task_setscheduler),
	LSM_HOOK_INIT(task_getscheduler, medusa_l1_task_getscheduler),
	LSM_HOOK_INIT(task_movememory, medusa_l1_task_movememory),
	LSM_HOOK_INIT(task_kill, medusa_l1_task_kill),
	LSM_HOOK_INIT(task_wait, medusa_l1_task_wait),
	LSM_HOOK_INIT(task_prctl, medusa_l1_task_prctl),
	LSM_HOOK_INIT(task_to_inode, medusa_l1_task_to_inode),

	LSM_HOOK_INIT(d_instantiate, medusa_l1_d_instantiate),

	LSM_HOOK_INIT(getprocattr, medusa_l1_getprocattr),
	LSM_HOOK_INIT(setprocattr, medusa_l1_setprocattr),

	LSM_HOOK_INIT(inode_notifysecctx, medusa_l1_inode_notifysecctx),
	LSM_HOOK_INIT(inode_setsecctx, medusa_l1_inode_setsecctx),
	LSM_HOOK_INIT(inode_getsecctx, medusa_l1_inode_getsecctx),
};

struct security_hook_list medusa_l1_hooks_special[] = {
	LSM_HOOK_INIT(inode_alloc_security, medusa_l1_inode_alloc_security),
	LSM_HOOK_INIT(inode_free_security, medusa_l1_inode_free_security),
	LSM_HOOK_INIT(cred_alloc_blank, medusa_l1_cred_alloc_blank),
	LSM_HOOK_INIT(cred_free, medusa_l1_cred_free),
};

void __init medusa_init(void);

static void medusa_l1_init_sb(struct super_block *sb, void *unused) {
        struct list_head *tmp;
        struct inode *entry;

	medusa_l1_sb_kern_mount(sb, 0, NULL);
	printk("medusa: sb: %s\n", sb->s_root->d_name.name);

        tmp = &sb->s_inodes;
        list_for_each(tmp, &sb->s_inodes) {
                entry = list_entry(tmp, struct inode, i_sb_list);
                if (&inode_security(entry)==NULL) {
                        medusa_l1_inode_alloc_security(entry);
                }
        }
}

// Number and order of hooks has to be the same
void security_replace_hooks(struct security_hook_list *old_hooks, struct security_hook_list *new_hooks, int count)
{
    int i;
    for (i = 0; i < count; i++)
        list_replace_rcu(&old_hooks[i].list, &new_hooks[i].list);
}

static int __init medusa_l1_init(void)
{
	struct task_struct* process;
	//struct inode* inode; unused JK march 2015

	/* register the hooks */	
	if (!security_module_enable("medusa"))
		return 0;
	
	security_add_hooks(medusa_l1_hooks, ARRAY_SIZE(medusa_l1_hooks));
	printk("medusa: l1 registered with the kernel\n");
    
    security_replace_hooks(medusa_l0_hooks, medusa_l1_hooks_special, ARRAY_SIZE(medusa_l1_hooks_special));

    extern bool l1_initialized;
    extern struct cred_list l0_cred_list;
    extern struct inode_list l0_inode_list;
    extern struct mutex l0_mutex;

    mutex_lock(&l0_mutex);

    struct list_head *pos, *q;
    struct inode_list *tmp;
    struct cred_list *tmp_cred;

    list_for_each_safe(pos, q, &l0_inode_list.list) {
        tmp = list_entry(pos, struct inode_list, list);
        medusa_l1_inode_alloc_security(tmp->inode);
        // printk("medusa: l1_alloc_security for an entry in the l0 list");
        list_del(pos);
        kfree(tmp); 
    }

    list_for_each_safe(pos, q, &l0_cred_list.list) {
        tmp_cred = list_entry(pos, struct cred_list, list);
        medusa_l1_cred_alloc_blank(tmp_cred->cred, tmp_cred->gfp);
        // printk("medusa: l1_cred_allo_blank for an entry in the l0 list");
        list_del(pos);
        kfree(tmp); 
    }

    l1_initialized = true;

    mutex_unlock(&l0_mutex);

	medusa_init();
    
	for_each_process(process) {
		struct medusa_l1_task_s* med;
		struct cred* tmp;

		if (&task_security(process) != NULL) {
			continue;
		}

		med = (struct medusa_l1_task_s*) kmalloc(sizeof(struct medusa_l1_task_s), GFP_KERNEL);

		if (med == NULL)
			return -ENOMEM;

		tmp = (struct cred*) process->cred;
		tmp->security = med;
		printk("medusa_init: task %s (pid %d)\n", process->comm, task_pid_nr(process));

		medusa_init_process(process);
	}

	iterate_supers(medusa_l1_init_sb, NULL);

	return 0;
}

static void __exit medusa_l1_exit (void)
{	
	printk("medusa unload");
	//security_delete_hooks(medusa_hooks, ARRAY_SIZE(medusa_hooks));
	return;
}



module_init (medusa_l1_init);
MODULE_LICENSE("GPL");
#endif /* CONFIG_SECURITY_MEDUSA */

