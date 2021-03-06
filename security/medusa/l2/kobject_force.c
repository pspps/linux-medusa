/* kobject_force.c, (C) 2002 Milan Pikula */

#include <linux/sched.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>

#include <linux/medusa/l3/registry.h>

#include <linux/medusa/l1/task.h> /* in fact, linux/sched includes that ;) */

#include "kobject_process.h"

#define MAX_FORCE_SIZE 16384	/* TODO: configurable size */

struct force_kobject {
	MEDUSA_KOBJECT_HEADER;

	pid_t pid;
	unsigned char code[MAX_FORCE_SIZE];
};

MED_ATTRS(force_kobject) {
	MED_ATTR_KEY_RO	(force_kobject, pid, "pid", MED_SIGNED),
	MED_ATTR	(force_kobject, code, "code", MED_BITMAP),

	MED_ATTR_END
};

static medusa_answer_t force_update(struct medusa_kobject_s * kobj)
{
	struct task_struct * p;
	medusa_answer_t retval;
	char * buf;

	printk("force: 1\n");
	retval = MED_ERR;
	read_lock_irq(&tasklist_lock);
	//p = find_task_by_pid(((struct force_kobject *)kobj)->pid);
	p = pid_task(find_vpid(((struct force_kobject *)kobj)->pid), PIDTYPE_PID);
	if (!p)
		goto out_unlock;
	printk("force: 2\n");
	if (task_security(p).force_code)
		goto out_unlock;
	printk("force: 3\n");
	buf = kmalloc(MAX_FORCE_SIZE, GFP_KERNEL);
	if (!buf)
		goto out_unlock;
	memcpy(buf, ((struct force_kobject *)kobj)->code, MAX_FORCE_SIZE);
	printk("force: 4 0x%.2x 0x%.2x 0x%.2x 0x%.2x\n",
		((struct force_kobject *)kobj)->code[0],
		((struct force_kobject *)kobj)->code[1],
		((struct force_kobject *)kobj)->code[2],
		((struct force_kobject *)kobj)->code[3]
	);
	task_security(p).force_code = buf;
	retval = MED_OK;
out_unlock:
	read_unlock_irq(&tasklist_lock);
	return retval;
}

MED_KCLASS(force_kobject) {
	MEDUSA_KCLASS_HEADER(force_kobject),
	"force",
	NULL,	/* init kclass */
	NULL,	/* destroy kclass */
	NULL,	/* fetch */
	force_update,
	NULL,	/* unmonitor */
};

int __init force_kobject_init(void) {
	MED_REGISTER_KCLASS(force_kobject);
	return 0;
}

__initcall(force_kobject_init);

