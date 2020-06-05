/*
 * Copyright (c) 2020, AT&T Intellectual Property. All rights reserved.
 */

#include <stdio.h>

#include "netconf_test.h"

void test_print(NC_VERB_LEVEL level, const char* msg)
{
	printf("\nNC ERROR:\n\n%s\n\n", msg);
}
