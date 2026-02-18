# in busy_box

make ARCH=m68k CROSS_COMPILE=m68k-linux-gnu- menuconfig


# In linux kernel
make -j$(nproc) ARCH=m68k CROSS_COMPILE=m68k-linux-gnu- vmlinux
make ARCH=m68k CROSS_COMPILE=m68k-linux-gnu- virt_defconfig
qemu-system-m68k \
    -M virt \
    -kernel vmlinux \
    -display none \
    -serial stdio \
    -append "console=ttyS0"
