#
# Copyright (c) 2020, AT&T Intellectual Property.
# All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-only

error_test_SRCS := \
	src/error_cpputest_wrapper.cpp \
	src/error_cpputest.c \
	src/netconf_test.c \
	src/mocks/vyatta_cfg_mocks.c \
	../configd/configd_datastore.c \
	../configd/configd_path.c \
	../configd/configd_xml_utils.c \

error_test_CFLAGS += -I/usr/include/libxml2 -I../configd
error_test_CFLAGS += -include /usr/include/CppUTest/MemoryLeakDetectorMallocMacros.h
error_test_CFLAGS += -Wall -Wextra -Wno-unused-parameter
error_test_CPPFLAGS += -I/usr/include/libxml2 -I../configd
error_test_CPPFLAGS += -include /usr/include/CppUTest/MemoryLeakDetectorMallocMacros.h

error_test_LDFLAGS += -lxml2 -lnetconf -lvyatta-util

TESTS += error_test

