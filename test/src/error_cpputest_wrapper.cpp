/*
 * Copyright (c) 2020, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * C++ wrapper around C unit tests.  Needed due to conflicts over 'new'
 * operator.
 */

#include "CppUTest/CommandLineTestRunner.h"
#include "CppUTest/TestHarness_c.h"

TEST_GROUP_C_WRAPPER(error)
{
    TEST_GROUP_C_SETUP_WRAPPER(error);    /** optional */
    TEST_GROUP_C_TEARDOWN_WRAPPER(error); /** optional */
};

/** For each C test, need to explicitly call the C code. */

TEST_C_WRAPPER(error, nc_err_from_mgmt_err_no_info);
TEST_C_WRAPPER(error, nc_err_from_mgmt_err_info);
TEST_C_WRAPPER(error, nc_err_from_mgmt_err_some_fields_missing);

TEST_C_WRAPPER(error, cfgd_basic_nc_err_with_err_text);
TEST_C_WRAPPER(error, cfgd_basic_nc_err_with_fallback_text);
TEST_C_WRAPPER(error, cfgd_basic_nc_err_with_no_text);

TEST_C_WRAPPER(error, build_reply_no_errors);
TEST_C_WRAPPER(error, build_reply_not_mgmt_error);
TEST_C_WRAPPER(error, build_reply_null_error_list);
TEST_C_WRAPPER(error, build_reply_error_is_null);
TEST_C_WRAPPER(error, build_reply_single_error);
TEST_C_WRAPPER(error, build_reply_multiple_errors);

TEST_C_WRAPPER(error, validate_fail);
TEST_C_WRAPPER(error, commit_fail);
TEST_C_WRAPPER(error, get_fail);
TEST_C_WRAPPER(error, get_config_fail);
