make -j6 ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- distclean
make -j6 ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- bcm2711_defconfig
make -j6 ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- Image modules dtbs



# build selftest
make -C tools/testing/selftests/ ARCH=arm64 all
