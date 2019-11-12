/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * C++ wrapper around C unit tests.
 */

#include "CppUTest/CommandLineTestRunner.h"
#include "CppUTest/TestHarness_c.h"

TEST_GROUP_C_WRAPPER(filter)
{
    TEST_GROUP_C_SETUP_WRAPPER(filter); /** optional */
    TEST_GROUP_C_TEARDOWN_WRAPPER(filter); /** optional */
};

/** For each C test, need to explicitly call the C code. */

TEST_C_WRAPPER(filter, rpc_not_get_or_get_config);
TEST_C_WRAPPER(filter, rpc_with_multiple_filter_elements);
TEST_C_WRAPPER(filter, rpc_with_non_filter_element);
TEST_C_WRAPPER(filter, rpc_with_xpath_filter);
TEST_C_WRAPPER(filter, rpc_with_empty_filter);
TEST_C_WRAPPER(filter, rpc_with_no_filter);
TEST_C_WRAPPER(filter, rpc_with_no_filter_type);
TEST_C_WRAPPER(filter, rpc_with_subtree_filter_type);

TEST_C_WRAPPER(filter, rpc_get_selection_node_single_tag);
TEST_C_WRAPPER(filter, rpc_get_selection_node_paired_tags);
TEST_C_WRAPPER(filter, rpc_get_attribute_match_node);
TEST_C_WRAPPER(filter, rpc_get_content_match_node);
TEST_C_WRAPPER(filter, rpc_get_config_specific_elements);
TEST_C_WRAPPER(filter, rpc_get_specific_elements);
TEST_C_WRAPPER(filter, rpc_get_specific_non_tagnode_element);
TEST_C_WRAPPER(filter, rpc_get_multiple_subtrees);
TEST_C_WRAPPER(filter, rpc_get_multiple_subtrees_divergent_paths);




