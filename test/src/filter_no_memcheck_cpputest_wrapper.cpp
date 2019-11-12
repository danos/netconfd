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

extern "C" {
#include "filter_no_memcheck_cpputest.h"
}

TEST_GROUP(filter_no_memcheck)
{
	void setup()
	{
		MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
	}

	void teardown()
	{
		MemoryLeakWarningPlugin::turnOnNewDeleteOverloads();
	}
};

TEST(filter_no_memcheck, check_configd_gets_correct_filter_wrapper)
{
	test_check_configd_gets_correct_filter();
}

