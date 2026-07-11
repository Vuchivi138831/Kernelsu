# 1. Gom tất cả các tệp nguồn cần thiết vào chung một module mang tên 'kernelsu'
kernelsu-objs := ksu.o
kernelsu-objs += allowlist.o
kernelsu-objs += apk_sign.o
kernelsu-objs += module_api.o
kernelsu-objs += sucompat.o
kernelsu-objs += uid_observer.o
kernelsu-objs += manager.o
kernelsu-objs += core_hook.o
kernelsu-objs += ksud.o
kernelsu-objs += embed_ksud.o
kernelsu-objs += kernel_compat.o

# 2. Khai báo phần xử lý SELinux đi kèm trong gói
kernelsu-objs += selinux/

# 3. Ép buộc hệ thống biên dịch đóng gói toàn bộ danh sách trên thành tệp 'kernelsu.o' để nhúng vào Kernel
obj-y += kernelsu.o

# Cấu hình xử lý lấy phiên bản Git tự động từ mã nguồn của bạn
ifeq ($(shell test -e $(srctree)/$(src)/../.git; echo $$?),0)
# We must use the absolute path to git, otherwise the build will fail if git is not in the PATH
KSU_GIT_VERSION := $(shell cd $(srctree)/$(src);/usr/bin/git rev-list --count HEAD)
ccflags-y += -DKSU_GIT_VERSION=$(KSU_GIT_VERSION)
endif

# Các cờ bỏ qua cảnh báo khi biên dịch (Giữ nguyên cấu hình của bạn)
ccflags-y += -Wno-implicit-function-declaration -Wno-strict-prototypes -Wno-int-conversion -Wno-gcc-compat
ccflags-y += -Wno-macro-redefined -Wno-declaration-after-statement
