
# Single makefile used by all the opensource
#
SPIDERPORK_ROOT ?= $(shell (cd ../../../../../../../ && pwd -P))
tgz := $(wildcard *.tar.gz) $(wildcard *.tgz) 
tbz := $(wildcard *.src.tar.bz2) $(wildcard *.tar.bz2)
zip := $(wildcard *.zip)
xz := $(wildcard *.tar.xz)

# we only extract the first archive if there are several
tarball := $(firstword $(tgz))

# the current dir.  we use this to customize this one makefile
pwd = $(shell pwd)
dir = $(shell basename $(pwd))


# find and include the toolchain.  Sets TCDIR, ARCH, etc.
toolchain_dir = $(dir $(wildcard ../*/istoolchain))
toolchain_name = $(patsubst ../%/,%,$(toolchain_dir))
EXPORT_ONLY := 1
include $(toolchain_dir)/Makefile.pub
EXPORT_ONLY :=

# set up path
TOOLCHAIN_PATH=$(pwd)/../$(TCDIR)/extracted/$(TCDIR2)/bin
TOOLCHAIN_PATH2=$(pwd)/../$(TCDIR)/extracted/$(TCDIR2)/$(TC)/bin

P := $(PATH)
export PATH=$(TOOLCHAIN_PATH):$(P)
export CC=gcc

# these can be referenced if needed
CROSS_COMPILE=$(TC)-
CC=$(CROSS_COMPILE)gcc
CXX=$(CROSS_COMPILE)g++
LD=$(CROSS_COMPILE)ld

# load any dependencies (have to include makefile.pub twice)
depends =
include Makefile.pub
EXPORT_ONLY := 1
include $(patsubst %,../%/Makefile.pub,$(depends))
EXPORT_ONLY :=

# these are builtin
builtin = expat openssl zlib ncurses libuuid

OPENSSL = $(wildcard $(pwd)/../openssl/extracted/*/include)
ZLIB = $(wildcard $(pwd)/../zlib/extracted/*/.)
NCURSES = $(wildcard $(pwd)/../ncurses/extracted/*/include)
LIBUUID = $(wildcard $(pwd)/../libuuid/extracted/*/lib)

# these next vars control dependencies and how packages are extracted,
# patched, configured and built.
# setting a value to /bin/true makes it a no-op.  
# default values follow:

extract = 
depends = 
fetch = 
patchlevel = 1
configure = /bin/false
build = /bin/false

# load the settings for this package
include Makefile.pub

# some builtins.

ifeq ($(dir),expat)
	fetch = wget -c http://downloads.sourceforge.net/expat/expat-2.0.1.tar.gz
	configure = CC=$(CC) LD=$(LD)  ./configure --host=arm-linux --enable-shared --enable-static
	build = cp -rf $(SPIDERPORK_ROOT)/lego_overlay/opensource/expat/patches ../../ ; for n in ../../patches/*.patch ; do patch -p$(patchlevel) < $$n || exit 1; done > ../../.patchlog ; make
endif
ifeq ($(dir),openssl)
	depends = zlib
	patch = sed -i 's/^);/"arm-generic32","$(TC)-gcc:-DTERMIO -O3 -fomit-frame-pointer -Wall::-D_REENTRANT::-ldl:BN_LLONG RC4_CHAR RC4_CHUNK DES_INT DES_UNROLL BF_PTR:$${no_asm}:dlfcn:linux-shared:-fPIC::.so.\\$$(SHLIB_MAJOR).\\$$(SHLIB_MINOR)");/' Configure && echo patching file Configure > ../../.patchlog
	fetch = wget -c http://www.openssl.org/source/old/0.9.x/openssl-0.9.8n.tar.gz
	configure = ./Configure arm-generic32 shared zlib-dynamic -DL_ENDIAN no-krb5 no-hw no-static_engine no-engine no-capieng no-cms no-rfc3779 no-perlasm no-ec no-err no-fips no-sse2 no-zlib -DOPENSSL_SMALL_FOOTPRINT -I$(ZLIB)
	build = make
endif
ifeq ($(dir),zlib)
	fetch = wget -c http://downloads.sourceforge.net/project/libpng/zlib/1.2.5/zlib-1.2.5.tar.gz
#	fetch = wget -c http://tcpdiag.dl.sourceforge.net/project/libpng/zlib/1.2.5/zlib-1.2.5.tar.gz
	configure = CC=$(CC) LD=$(LD) ./configure 
	build = make
endif
ifeq ($(dir),ncurses)
	fetch = wget -c http://ftp.gnu.org/pub/gnu/ncurses/ncurses-5.6.tar.gz
	configure = CC=$(CC) ./configure --target=$(TC) --host=$(TC) --with-build-cc=gcc --with-shared --without-debug --with-terminfo-dirs=/usr/share/terminfo --with-default-terminfo-dir=/usr/share/terminfo --without-ada
	build = make && ln -s curses.h include/ncurses.h
endif
ifeq ($(dir),libuuid)
	fetch = wget -c http://downloads.sourceforge.net/project/e2fsprogs/e2fsprogs/1.41.8/e2fsprogs-1.41.8.tar.gz
	patch = sed -i -e 's: intl$$: \# modified by Cisco Systems, Inc. on 07/19/2012:' Makefile.in
	configure = ./configure --prefix=/ \
		--host=$(TC) \
		--target=$(TC) \
		--with-cc="$(CC)" \
		--with-linker="$(LD)" \
		--with-ccopts="$(ARCH_CFLAGS) -DHAVE_SYSCONF" \
		--disable-nls \
		--enable-dynamic-e2fsck \
		--enable-elf-shlibs \
		--disable-tls
	build = make
endif

# everything depends on the toolchain
ifneq ($(dir),$(toolchain_name))
depends := $(toolchain_name) $(depends)
endif

#
#  The actual rules to generically build things
#

all::	.built

depends_built = $(patsubst %,../%/.built,$(depends))
.depends:	$(depends_built)
	touch $@

../%/.built:
	make -C ../$*

.fetched:
ifdef fetch
	$(fetch)
endif
	touch $@

.extracted:	$(tarball) .depends
ifdef extract
	$(extract)
else
	mkdir -p extracted
	for n in $(tgz); do tar xvfz $$n -C extracted || exit 1; done
	for n in $(tbz); do tar xvfB $$n -C extracted || exit 1; done
	for n in $(zip); do unzip $$n -d extracted || exit 1; done
	for n in $(xz); do tar xvf $$n -C extracted || exit 1; done
endif
	touch $@
	sleep 1		# needed to make sure timestamps differ by at least 1 sec for checkpatches

.patched:	.extracted
	> .patchlog
ifdef patch
ifeq ($(dir),arm-2007q1)
	cd extracted/$(dir)/ && $(patch)
else
	cd extracted/*/ && $(patch)
endif
else
ifneq ($(wildcard patches/*),)
ifeq ($(dir),arm-2007q1)
	cd extracted/$(dir)/ && for n in ../../patches/*; do patch -p$(patchlevel) < $$n || exit 1; done > ../../.patchlog
else
	cd extracted/*/ && for n in ../../patches/*; do patch -p$(patchlevel) < $$n || exit 1; done > ../../.patchlog
endif
endif
endif
	cd extracted/*/ && ../../../../patchlog < ../../.patchlog
	../../checkpatches
	touch $@

.configured:	.patched
	cd extracted/*/ && $(configure)
	touch $@

.built:	.configured
	cd extracted/*/ && $(build)
	touch $@

clean::
	rm -rf .extracted .patched .patchlog .configured .built extracted .depends

env:
	env

#
# special prerequisites we don't redistribute
#
$(patsubst %,../%/.built,$(builtin)): ../%/.built:
	mkdir -p `dirname $@`
	test -L `dirname $@`/Makefile || ln -s ../../Makefile.src `dirname $@`/Makefile
	test -L `dirname $@`/Makefile.pub || touch `dirname $@`/Makefile.pub
	make -C `dirname $@` .fetched
	test -L `dirname $@`/Makefile.pub || touch `dirname $@`/Makefile.pub
	make -C `dirname $@`

$(patsubst %,../%/Makefile.pub,$(builtin)):
	mkdir -p `dirname $@`
	touch $@
