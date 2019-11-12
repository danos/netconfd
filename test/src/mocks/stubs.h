/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Generic stub macros that are used in all functions thrown out by the
 * linker as undefined.  This allows you to get a build running quickly,
 * and you replace the stub macro with mock_c() calls only when the macro
 * is called and asserts.
 */
#if !defined(__stubs_h__)
#define __stubs_h__

#include "assert.h"
#include "CppUTestExt/MockSupport_c.h"

#define CPPUTEST_STUB_RET_VAL(val)					\
	__extension__							\
	({								\
		fprintf(stderr, "\n*** %s not yet implemented ***\n", __func__); \
		assert(0);						\
		return val;						\
	})

#define CPPUTEST_STUB_RET						\
	__extension__							\
	({								\
		fprintf(stderr, "\n*** %s not yet implemented ***\n", __func__); \
		assert(0);						\
		return;							\
	})


#endif
