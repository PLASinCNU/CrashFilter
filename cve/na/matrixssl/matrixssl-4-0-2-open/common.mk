##
# Common Makefile definitions.
# @version 1518527 (tag: 4-0-2-open)
# Copyright (c) 2013-2017 INSIDE Secure Corporation. All Rights Reserved.
#
#-------------------------------------------------------------------------------

# Find core library.
-include corepath.mk

ifeq '$(CORE_PATH)' ''
CORE_PATH:=$(patsubst %/,%/core,$(dir $(lastword $(MAKEFILE_LIST))))
endif

# The common.mk is replaced by equivalent functionality within core.
include $(CORE_PATH)/makefiles/detect-and-rules.mk
