#ifndef PATH_TOOLS_H
#define PATH_TOOLS_H

#define MEDUSA_DENTRY_PTR_TO_INODE_PTR(dentry) ((dentry)->d_inode)

#define MEDUSA_PATH_PTR_TO_DENTRY_PTR(path) ((path)->dentry)
#define MEDUSA_PATH_PTR_TO_INODE_PTR(path) MEDUSA_DENTRY_PTR_TO_INODE_PTR(MEDUSA_PATH_PTR_TO_DENTRY_PTR(path))
#define MEDUSA_PATH_PTR_TO_FS_PTR(path) ((path)->mnt)

#define MEDUSA_FILE_PTR_TO_INODE_PTR(file) ((file)->f_inode)
#define MEDUSA_FILE_PTR_TO_PATH_PTR(file) ((file)->f_file)
#define MEDUSA_FILE_PTR_TO_DENTRY_PTR(file) MEDUSA_PATH_PTR_TO_DENTRY_PTR(MEDUSA_FILE_PTR_TO_PATH_PTR(file))
#define MEDUSA_FILE_PTR_TO_FS_PTR(file) MEDUSA_PATH_PTR_TO_FS_PTR(MEDUSA_FILE_PTR_TO_PATH_PTR(file))


#if 0
#define MEDUSA_CREATE_PATH_NAME_INSTANCE(name) do ({\
	struct medusa_path_name *ret = (struct medusa_path_name*) kmalloc(sizeof(struct medusa_path_name), GFP_KERNEL);\
	if(ret != NULL) {\
		ret->name = {0};\
		ret->list = LIST_HEAD_INIT(ret->list);\
	}\
	ret;\
})

struct medusa_path_name {
	//TODO normalne zadat velkost
	char name[256];
	struct list_head list;
};
#endif

#endif
