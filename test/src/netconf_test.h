/*
 * Copyright (c) 2020, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <libnetconf.h>

#define XML_RPC_START_TAG                                           \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"                    \
    "<nc:rpc xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" " \
    "    message-id=\"urn:uuid:f5a7861b-43ed-47f5-93dc-fbc30e1c4720\">"
#define XML_RPC_END_TAG "</nc:rpc>"

#define XML_RPC_GET_SUBTREE_START_TAG                                   \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"                        \
    "<nc:rpc xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "     \
    "    message-id=\"urn:uuid:f5a7861b-43ed-47f5-93dc-fbc30e1c4720\">" \
    "  <nc:get>"                                                        \
    "    <nc:filter type=\"subtree\">"
#define XML_RPC_GET_SUBTREE_END_TAG \
    "    </nc:filter>"              \
    "  </nc:get>"                   \
    "</nc:rpc>"

// get-config requires <source> to be present
#define XML_RPC_GET_CFG_SUBTREE_START_TAG                           \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"                    \
    "<nc:rpc xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" " \
    "    message-id=\"101\">"                                       \
    "  <nc:get-config>"                                             \
    "    <nc:source><nc:running/></nc:source>"                      \
    "    <nc:filter type=\"subtree\">"
#define XML_RPC_GET_CFG_SUBTREE_END_TAG \
    "    </nc:filter>"                  \
    "  </nc:get-config>"                \
    "</nc:rpc>"

#define MAP_NOT_TAG NULL
#define NO_INFO NULL

void test_print(NC_VERB_LEVEL level, const char *msg);
