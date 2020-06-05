/*
 * Copyright (c) 2020, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Tests which we can't have memory detection enabled on as they allocate
 * memory in functions such as asprintf() which CppUTest can't track.
 */

#include "CppUTest/CommandLineTestRunner.h"
#include "CppUTest/TestHarness.h"

extern "C"
{
#include "error_no_memcheck_cpputest.h"
}

TEST_GROUP(error_no_memcheck)
{
	void setup()
	{
		MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
	}

	void teardown()
	{
		MemoryLeakWarningPlugin::turnOnNewDeleteOverloads();
	}

	void dummyFunctionToKeepVSCodeFormattingHappy();
};

// nc_rpc_get_config allocates memory in a way cpputest can't track so we have
// to disable memory checking for this test.  Mixing tests that do and don't
// use memory checking in the same make file cause weird errors so best kept
// in separate files.
//
// Usually it's asprintf() that we can't track.
//
TEST(error_no_memcheck, check_edit_config_fail)
{
	test_edit_config_fail();
}

TEST(error_no_memcheck, check_get_direct_fail)
{
	test_get_fail_direct();
}
