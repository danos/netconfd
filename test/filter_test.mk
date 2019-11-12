#
# Copyright (c) 2018, AT&T Intellectual Property.
# All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-only

filter_test_SRCS := \
	src/filter_cpputest.c \
	src/filter_cpputest_wrapper.cpp \
	src/mocks/vyatta_cfg_mocks.c \
	../configd/configd_datastore.c \
	../configd/configd_path.c \

filter_test_CFLAGS += -I/usr/include/libxml2 -I../configd
filter_test_CFLAGS += -include /usr/include/CppUTest/MemoryLeakDetectorMallocMacros.h
filter_test_CFLAGS += -Wall -Wextra -Wno-unused-parameter
filter_test_CPPFLAGS += -I/usr/include/libxml2 -I../configd
filter_test_CPPFLAGS += -include /usr/include/CppUTest/MemoryLeakDetectorMallocMacros.h

filter_test_LDFLAGS += -lxml2 -lnetconf -lvyatta-util

TESTS += filter_test

