/*
 *  dummymod.c
 *
 *  Solary dummy (and vulnerable) module code. Creates a pseudo device in
 *  /devices/pseudo/dummy0:0 which can be attacked by vulnerable IOCTL calls. 
 *
 * To compile and install (with SunStudio, on a amd64 64-bit kernel) use:
 *
 * # cc -D_KERNEL -m64 -xmodel=kernel -c dummymod.c
 * # /usr/bin/ld -r -o dummy dummymod.o
 *
 * and then:
 * # cp dummy /kernel/drv/amd64/
 * # cp dummy.conf /kernel/drv/
 * # add_drv -m '* 0644 root sys' dummy
 *
 * At this point pseudo device has been created:
 * # ls -l /devices/pseudo/dummy\@0\:0 
 * crw-r--r-- 1 root sys 302, 0 2010-09-24 02:33 /devices/pseudo/dummy@0:0
 *
 * To "remove" use rem_drv
 * # rem_drv dummy
 */

#include <sys/devops.h>  
#include <sys/conf.h>   
#include <sys/modctl.h> 
#include <sys/types.h>  
#include <sys/file.h>  
#include <sys/errno.h>
#include <sys/open.h>   
#include <sys/cred.h>  
#include <sys/uio.h>  
#include <sys/stat.h>   
#include <sys/cmn_err.h> 
#include <sys/ddi.h>     
#include <sys/sunddi.h>  

#include "dummymod.h"

static int test_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int test_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int test_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
	void **resultp);
static int test_open(dev_t *devp, int flag, int otyp, cred_t *cred);
static int test_close(dev_t dev, int flag, int otyp, cred_t *cred);
static int test_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
	cred_t *cred_p, int *rval_p );

static struct cb_ops test_cb_ops = {
	test_open,
	test_close,
	nodev,              /* no stragegy */
	nodev,              /* no print */
	nodev,              /* no dump */
	nodev,
	nodev,
	test_ioctl,     
	nodev,              /* no devmap */
	nodev,              /* no mmap */
	nodev,              /* no segmap */
	nochpoll,           
	ddi_prop_op,
	NULL,             
	D_NEW | D_MP,       
	CB_REV,             /* cb_ops revision number */
	nodev,              /* no aread */
	nodev               /* no awrite */
};

static struct dev_ops test_dev_ops = {
	DEVO_REV,
	0,                  /* reference count */
	test_getinfo,
	nulldev,            /* no identify - nulldev returns 0 */
	nulldev,            /* no probe */
	test_attach,
	test_detach,
	nodev,              /* no reset - nodev returns ENXIO */
	&test_cb_ops,
	(struct bus_ops *)NULL,
	nodev               /* no power */
};

static struct modldrv md = {
	&mod_driverops,			/* Type of module. This is a driver. */
	"vulnerable dummy module",     /* Name of the module. */
	&test_dev_ops
};

/* modlinkage structure */
static struct modlinkage ml = {
	MODREV_1,
	&md,
	NULL
};

/* dev_info structure */
dev_info_t *test_dip;  /* keep track of one instance */


/* Loadable module configuration entry points */
int
_init(void)
{
    cmn_err(CE_NOTE, "Loading dummy vulnerable module...");
    return (mod_install(&ml));
}

int
_info(struct modinfo *modinfop)
{
    return (mod_info(&ml, modinfop));
}

int
_fini(void)
{
    cmn_err(CE_NOTE, "Unloading dummy vulnerable module...");
    return(mod_remove(&ml));
}

/* Device configuration entry points */
static int
test_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
    switch(cmd) {
		case DDI_ATTACH:
			test_dip = dip;
			if (ddi_create_minor_node(dip, "0", S_IFCHR,
			    ddi_get_instance(dip), DDI_PSEUDO,0) != DDI_SUCCESS)
				return (DDI_FAILURE);
			else
				return (DDI_SUCCESS);
		default:
			return DDI_FAILURE;
    }
}

static int
test_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
    cmn_err(CE_NOTE, "Inside test_detach");
    switch(cmd) {
		case DDI_DETACH:
			test_dip = 0;
			ddi_remove_minor_node(dip, NULL);
			return (DDI_SUCCESS);
		default:
			return (DDI_FAILURE);
    }
}

static int
test_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
	void **resultp)
{
    cmn_err(CE_NOTE, "Inside test_getinfo");
    switch(cmd) {
		case DDI_INFO_DEVT2DEVINFO:
			*resultp = test_dip;
			return (DDI_SUCCESS);
		case DDI_INFO_DEVT2INSTANCE:
			*resultp = 0;
			return (DDI_SUCCESS);
		default:
			return (DDI_FAILURE);
    }
}

/*
 * Pretty darn dummy...
 */
static int
test_open(dev_t *devp, int flag, int otyp, cred_t *cred)
{
    return (DDI_SUCCESS);
}

static int
test_close(dev_t dev, int flag, int otyp, cred_t *cred)
{
    return (DDI_SUCCESS);
}

#define	STACKBUF	(32)

static int handle_stack (intptr_t arg)
{
	char			buf[STACKBUF];
	struct	test_request	req;
	
	ddi_copyin((void *)arg, &req, sizeof(struct test_request), 0);
	cmn_err(CE_CONT, "Requested to copy over buf %d bytes from %p\n",
	    req.size, &buf);	
	ddi_copyin((void *)req.addr, buf, req.size, 0);
	
	return (0);
} 

static void alloc_heap_buf (intptr_t arg)
{
	char			*buf;
	struct test_request	req;
	
	ddi_copyin((void *)arg, &req, sizeof(struct test_request), 0);
	buf = kmem_alloc(req.size, KM_SLEEP);
	req.addr = (unsigned long)buf;
	ddi_copyout(&req, (void *)arg, sizeof(struct test_request), 0);
}

static void free_heap_buf (intptr_t arg)
{
	char			*buf;
	struct test_request	req;
	
	ddi_copyin((void *)arg, &req, sizeof(struct test_request), 0);
	buf = (char *)req.addr;
	kmem_free(buf, req.size);
}


static void handle_heap_ovf (intptr_t arg)
{
	char			*buf;
	struct test_request	req;
	
	ddi_copyin((void *)arg, &req, sizeof(struct test_request), 0);
	buf = kmem_alloc(64, KM_SLEEP);
	cmn_err(CE_CONT, "performing heap ovf at %p\n", buf);
	ddi_copyin((void *)req.addr, buf, req.size, 0);
}	
	
static int test_ioctl (dev_t dev, int cmd, intptr_t arg, int mode,
	cred_t *cred_p, int *rval_p )
{
	switch (cmd) {
		case TEST_STACKOVF:
			cmn_err(CE_CONT,"ioctl: requested STACKOVF test\n");
			handle_stack(arg);      
			break;
		case TEST_ALLOC_SLAB_BUF:			
			alloc_heap_buf(arg);
			break;
		case TEST_FREE_SLAB_BUF:
			free_heap_buf(arg);
			break;
		case TEST_SLABOVF:
			cmn_err(CE_CONT, "ioctl: requested HEAPOVF test\n");
			handle_heap_ovf(arg);
			break;
		case TEST_NULLDRF:
			break;
		default:
			return (DDI_FAILURE);
	}
	
	return DDI_SUCCESS;
}
