#/** @file Makefile
#  *
#  * @brief This file contains WLAN driver specific defines etc.
#  *
#  * Copyright 2018-2020 NXP
#  *
#  * This software file (the "File") is distributed by NXP
#  * under the terms of the GNU General Public License Version 2, June 1991
#  * (the "License").  You may use, redistribute and/or modify the File in
#  * accordance with the terms and conditions of the License, a copy of which
#  * is available by writing to the Free Software Foundation, Inc.,
#  * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA or on the
#  * worldwide web at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
#  *
#  * THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE
#  * IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE
#  * ARE EXPRESSLY DISCLAIMED.  The License provides additional details about
#  * this warranty disclaimer.
#  *
#  */


# Default build target if no target is specified at command line
.PHONY: default
default: all



#vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
# Main configuration - BEGIN

PRODUCT              ?= W9068
export PROJECT_NAME  := Marvell $(PRODUCT) SMAC API

export TOOLS_DIR     := tools
export RESOURCES_DIR := $(TOOLS_DIR)/resources
export DOC_DIR       := doc

# Main configuration - END
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



#vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
#vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
# Derived configuration - BEGIN


# Derived configuration - END
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



#vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
# Environment configuration and tools - BEGIN

ifdef WINDIR
  UNAME_S := $(shell uname -s)

  ifeq ($(UNAME_S),CYGWIN_NT-6.1)
    ENVIRONMENT := CygWin
    NATIVE_PATH = $(1)
    _RM         = /bin/rm -rf $(1)
    _MD         = /bin/mkdir -p $(1)
  else
    ENVIRONMENT := Windows
    NATIVE_PATH = $(subst /,\,$(1))
    _RM         = $(foreach f, $(1), ( if exist $(f) del /q /s $(f) ) &)
    _MD         = $(foreach f, $(1), ( if not exist $(1) mkdir $(1) ) &)
  endif
else
  ifdef windir
    ENVIRONMENT := Windows
    NATIVE_PATH  = $(subst /,\,$(1))
    _RM          = $(foreach f, $(1), ( if exist $(f) del /q /s $(f) ) &)
    _MD          = $(foreach f, $(1), ( if not exist $(1) mkdir $(1) ) &)
  else
    ENVIRONMENT := Linux
    NATIVE_PATH  = $(1)
    _RM          = /bin/rm -rf $(1)
    _MD          = /bin/mkdir -p $(1)
  endif
endif

RM = $(call _RM, $(call NATIVE_PATH, $(1)))
MD = $(call _MD, $(call NATIVE_PATH, $(1)))

# Environment configuration and tools - END
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



#vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
# Sub targets - BEGIN

_SUB_TARGETS += doc

doc-all:
	doxygen $(TOOLS_DIR)/doxygen/doxygen.cfg
	@echo $(PROJECT_NAME), DOC successfully built

doc-clean:
	$(call RM, $(DOC_DIR))
	@echo $(PROJECT_NAME), DOC cleaned

.PHONY: $(_SUB_TARGETS)
.PHONY: $(_SUB_TARGETS:%=%-all)
.PHONY: $(_SUB_TARGETS:%=%-clean)

.SECONDEXPANSION:
$(_SUB_TARGETS): $$(@)-all

# Sub targets - END
#vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv



#vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
# Main targets - BEGIN

.PHONY: all
all: $(_SUB_TARGETS:%=%-all)
	@echo $(PROJECT_NAME) successfully built

.PHONY: doc
clean: $(_SUB_TARGETS:%=%-clean)
	@echo $(PROJECT_NAME) cleaned

# Main targets - END
#vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
