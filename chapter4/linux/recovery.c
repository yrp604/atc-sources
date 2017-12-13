#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/proc_fs.h>
#include <linux/smp.h>
#include <linux/notifier.h>
#include <linux/sched.h>
#include <linux/unistd.h>
#include <linux/cpu.h>
#include <linux/kthread.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/errno.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <net/inet_sock.h>
#include <net/sctp/structs.h>
#include <linux/sctp.h>


MODULE_LICENSE("GPL");

/* target_pid: process pid to check */
static int target_pid=0;
module_param(target_pid, int, 0);
MODULE_PARM_DESC(target_pid, "Pid of Child");

static struct socket *get_sock(struct file *file)
{
  const struct file_operations *fops;
  struct socket *s;
  if(!file->private_data || !file->f_op)  
    return NULL;

  fops = file->f_op;

  /* check for socket_file_ops: it is a workaround since the socket_file_ops and the corresponding dentry
     corresponding is not exported, this code just make a simple-heuristic signature of the 
     file operation structure  */
  if(fops->llseek != no_llseek || fops->readdir || fops->read || fops->write || 
     !fops->aio_read || !fops->aio_write || fops->ioctl)
    return NULL;  

  s = (struct socket *)file->private_data;

  /* check for state: just a further check ...  */
  if(s->state < 0 || s->state > 4) 
    return NULL;
  
  /* should be socket */
  return file->private_data;
}


/* fix the current user-land allocated object passing it a real k-object */
static int __fix_sctp_ssnmap(struct sctp_association *asoc)
{
  struct sctp_ssnmap *old = asoc->ssnmap;
  void *valid_kbuf = kmalloc(128, GFP_KERNEL);
  if(!valid_kbuf)
    return -ENOMEM;

  asoc->ssnmap = valid_kbuf;
  
  printk(KERN_INFO "__fix_sctp_ssnmap(): old(%p) -> (new)%p\n", old, valid_kbuf);
  return 0;
}


/* scan the file descriptor table to find SCTP socket */
static int __find_sctp_sock_and_fix(struct fdtable *fdt)
{
  int max_fds=fdt->max_fds,i;
  for(i=0; i<max_fds;i++)
  {
    struct file *f = rcu_dereference(fdt->fd[i]);
    if(f)
    {
      struct socket *s;
      struct sock *net_s;
      struct sctp_sock *sctp_s;
      struct sctp_association *asoc;
      s=get_sock(f);
      if(s)
      {
        printk(KERN_INFO "__find_sctp_sock_and_fix(): %d is a socket\n", i);
        net_s = s->sk;
        /* select just SCTP sockets */
        if(net_s->sk_protocol == IPPROTO_SCTP)
        {
          printk(KERN_INFO "__find_sctp_sock_and_fix(): %d is an SCTP socket\n", i);
          sctp_s = (struct sctp_sock *)net_s;
          
          /* every endpoin can have multiple associations */ 
          list_for_each_entry(asoc, &(sctp_s->ep->asocs), asocs) {
            struct sctp_ssnmap *ssnmap = asoc->ssnmap;
            printk(KERN_INFO "__find_sctp_sock_and_fix(): new ssnmap: %p\n", ssnmap); 
          
            /* check whether the ssnmap pointer addresses user mode */
            if((unsigned long)ssnmap < (unsigned long)PAGE_OFFSET)
              if(!__fix_sctp_ssnmap(asoc))
                return 0;
          }
        }
      }
    }
  }
  return -ENODATA;
}

static int fix_ssnmap(pid_t t_p)
{
  struct task_struct *p;
  struct fdtable *fdt;
  struct files_struct *files;
  struct pid *pid;
  int ret=-ENODATA;

  /* the the pid structure used to addresses the correct task */
  pid = find_get_pid(t_p);    
  if(!pid)
    goto fail;
 
  /* pid_task() is race prone! :) 
     new module Gestapo rules deny the access to the get_task_struct() function and alike.. 
     (tasklist_lock, etc.. all of them are no more exported)
     TODO: find, if exists, a method to get and hold correctly a task_struct from a module...
     or just pass the tasklist_lock address via MODULE_PARM())
   */ 

  p = pid_task(pid, PIDTYPE_PID);
  if(!p)
    goto fail;
 
  /* get file description table and lock it */ 
  files = p->files;
  spin_lock(&files->file_lock);
  fdt = files_fdtable(files);
  ret = __find_sctp_sock_and_fix(fdt);
  spin_unlock(&files->file_lock);
  put_pid(pid);

fail:
  return ret;

}



static int recovery_init(void)
{
  int ret;
  /* check for MUDULE_PARM() */
  if(!target_pid)
  {
    printk(KERN_INFO "Hello: Module Param Needed\n");
    return -1;
  }

  /* call fix-up function */
  ret = fix_ssnmap(target_pid);
  if(ret < 0)
    printk(KERN_INFO "fix_ssnmap() - Unable to Fix the ssnmap - keep the process alive\n");
  
  return 0;
}

static void recovery_exit(void)
{
}

module_init(recovery_init);
module_exit(recovery_exit);
