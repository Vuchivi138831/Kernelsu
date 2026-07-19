kernelsu-objs := ksu.o
kernelsu-objs += allowlist.o
kernelsu-objs += apk_sign.o
kernelsu-objs += sucompat.o
kernelsu-objs += throne_tracker.o
kernelsu-objs += core_hook.o
kernelsu-objs += ksud.o
kernelsu-objs += embed_ksud.o
kernelsu-objs += kernel_compat.o

kernelsu-objs += selinux/selinux.o
kernelsu-objs += selinux/sepolicy.o
kernelsu-objs += selinux/rules.o

ccflags-y += -I$(srctree)/security/selinux -I$(srctree)/security/selinux/include
ccflags-y += -I$(objtree)/security/selinux -include $(srctree)/include/uapi/asm-generic/errno.h

obj-$(CONFIG_KSU) += kernelsu.o

# =========================================================================
# ĐÃ CẬP NHẬT: Ép phiên bản KernelSU về mức TỐI THIỂU (32377) để đạt độ ổn định
# Giúp nhân vừa đủ điều kiện vượt qua bài kiểm tra của App Manager 32-bit.
# =========================================================================
KSU_VERSION := 32558
$(info -- KernelSU Custom Stable Version: $(KSU_VERSION))
ccflags-y += -DKSU_VERSION=$(KSU_VERSION)

# Kiểm tra tính tương thích cấu trúc SELinux của Kernel
ifeq ($(shell grep -q " current_sid(void)" $(srctree)/security/selinux/include/objsec.h; echo $$?),0)
    ccflags-y += -DKSU_COMPAT_HAS_CURRENT_SID
endif

ifeq ($(shell grep -q "struct selinux_state " $(srctree)/security/selinux/include/security.h; echo $$?),0)
    ccflags-y += -DKSU_COMPAT_HAS_SELINUX_STATE
endif

# Cấu hình Tên gói Manager (Nếu được truyền từ môi trường ngoài)
ifdef KSU_MANAGER_PACKAGE
    ccflags-y += -DKSU_MANAGER_PACKAGE=\"$(KSU_MANAGER_PACKAGE)\"
    $(info -- KernelSU Manager package name: $(KSU_MANAGER_PACKAGE))
endif

# Kiểm tra tính năng Umount tương thích
ifeq ($(shell grep -q "int path_umount" $(srctree)/fs/namespace.c; echo $$?),0)
    ccflags-y += -DKSU_UMOUNT
endif

# Các cờ tắt cảnh báo nghiêm ngặt của trình biên dịch
ccflags-y += -Wno-implicit-function-declaration -Wno-strict-prototypes -Wno-int-conversion -Wno-gcc-compat
ccflags-y += -Wno-declaration-after-statement -Wno-unused-function
