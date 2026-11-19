// hexdrv.c (in-tree built-in) — ring-0 memory access.
// ioctl READ/WRITE of another process's memory via access_process_vm().
// Built into the kernel (CONFIG_HEXDRV=y): not listed in /proc/modules.
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/ioctl.h>
#include <linux/init.h>

#define HEX_IOC_MAGIC 'H'
struct hex_req {
    int pid;
    unsigned long addr;
    unsigned long len;
    void __user *buf;
};
#define HEX_READ  _IOWR(HEX_IOC_MAGIC, 1, struct hex_req)
#define HEX_WRITE _IOWR(HEX_IOC_MAGIC, 2, struct hex_req)

static struct task_struct *hex_get_task(int pid) {
    struct task_struct *t;
    rcu_read_lock();
    t = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (t) get_task_struct(t);
    rcu_read_unlock();
    return t;
}

static long hex_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    struct hex_req r;
    struct task_struct *t;
    void *kbuf;
    int ret;

    if (copy_from_user(&r, (void __user *)arg, sizeof(r))) return -EFAULT;
    if (r.len == 0 || r.len > (4u * 1024u * 1024u)) return -EINVAL;

    t = hex_get_task(r.pid);
    if (!t) return -ESRCH;

    kbuf = kmalloc(r.len, GFP_KERNEL);
    if (!kbuf) { put_task_struct(t); return -ENOMEM; }

    if (cmd == HEX_READ) {
        ret = access_process_vm(t, r.addr, kbuf, r.len, 0);
        if (ret > 0 && copy_to_user(r.buf, kbuf, ret)) ret = -EFAULT;
    } else if (cmd == HEX_WRITE) {
        if (copy_from_user(kbuf, r.buf, r.len)) ret = -EFAULT;
        else ret = access_process_vm(t, r.addr, kbuf, r.len, FOLL_FORCE | FOLL_WRITE);
    } else {
        ret = -EINVAL;
    }

    kfree(kbuf);
    put_task_struct(t);
    return ret;
}

static const struct file_operations hex_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = hex_ioctl,
};

static struct miscdevice hex_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "hexdrv",
    .fops  = &hex_fops,
    .mode  = 0600,
};

static int __init hex_init(void) {
    return misc_register(&hex_misc);
}
device_initcall(hex_init);