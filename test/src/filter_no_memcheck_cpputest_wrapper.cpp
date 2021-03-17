/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property. All rights reserved.
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
#include "filter_no_memcheck_cpputest.h"
}

TEST_GROUP(filter_no_memcheck)
{
	void setup()
	{
		//Appears with Debian 11 rework that we no longer need to disable
		//memory leak detection. However, this is a brittle area so leaving
		//infrastructure in place, commented out, just in case.//MemoryLeakWarningPlugin::saveAndDisableNewDeleteOverloads();
	}

	void teardown()
	{
		//MemoryLeakWarningPlugin::restoreNewDeleteOverloads();
	}

	void dummyFunctionToKeepVSCodeFormattingHappy();
};

TEST(filter_no_memcheck, check_configd_gets_correct_filter_wrapper)
{
	//IGNORE_ALL_LEAKS_IN_TEST();
	test_check_configd_gets_correct_filter();
}
