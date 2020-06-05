#
# Copyright (c) 2018, AT&T Intellectual Property.
# All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#

filter_no_memcheck_test_SRCS := \
	src/filter_no_memcheck_cpputest.c \
	src/filter_no_memcheck_cpputest_wrapper.cpp \
	src/netconf_test.c \
	src/mocks/vyatta_cfg_mocks.c \
	../configd/configd_datastore.c \
	../configd/configd_path.c \
	../configd/configd_xml_utils.c \

filter_no_memcheck_test_CFLAGS += -I/usr/include/libxml2 -I../configd
filter_no_memcheck_test_CFLAGS += -Wall -Wextra -Wno-unused-parameter

filter_no_memcheck_test_CPPFLAGS += -I/usr/include/libxml2 -I../configd

filter_no_memcheck_test_LDFLAGS += -lxml2 -lnetconf -lvyatta-util

TESTS += filter_no_memcheck_test

