* Format of Build commands:
	- make all ARCH=[arch_config] KDIR=[kernel_dir] CROSS_COMPILE=[toolchain_dir] PWD=$PWD SOC=[soc_id]

	- [soc_id] configuration:
		For W906x:	SOC=W906x
		For W8964:	SOC=W8964

		If SOC build parameter is not specified, default value is SOC=W906x

	- Examples of build script:
		1. W906x in A3900 paltform:
			CROSS_COMPILE=/marvell-gcc-5.2.1-16.02.0/armv8/le/aarch64v8-marvell-linux-gnu-5.2.1_i686_20151110/bin/aarch64-marvell-linux-gnu-
			KDIR= /A3900-201710-Alpha-1
			make clean SOC=W906x
			make all ARCH=arm64 KDIR=$KDIR CROSS_COMPILE=$CROSS_COMPILE PWD=$PWD SOC=W906x
			if [ -f "ap8x.ko" ]; then
				${CROSS_COMPILE}strip --strip-debug ap8x.ko
			fi


		2. W8964 in A385 platform:
			CROSS_COMPILE=/armv7-marvell-linux-gnueabi-softfp_i686_64K_Dev_20131002/bin/arm-marvell-linux-gnueabi-
			KDIR=/linux-v3.10.39-2014_T3.0p5/
			make clean SOC=W8964
			make all ARCH=arm KDIR=$KDIR CROSS_COMPILE=$CROSS_COMPILE PWD=$PWD SOC=W8964
			if [ -f "ap8x.ko" ]; then
				${CROSS_COMPILE}strip -g ap8x.ko
			fi

