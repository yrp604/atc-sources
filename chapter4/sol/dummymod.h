/*
 * dummymod.h
 *
 * Used by both the kernel land module and the user land exploit.
 */

#ifndef	_TESTKE_H
#define	_TESTKE_H	1

enum {
	TEST_NULLDRF = 1,
	TEST_STACKOVF,
	TEST_SLABOVF,
	TEST_ALLOC_SLAB_BUF,
	TEST_FREE_SLAB_BUF
};

struct test_request {
	int		size;
	unsigned long	addr;
};

#endif
