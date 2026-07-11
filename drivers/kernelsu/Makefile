obj-y += ksu.o
obj-y += allowlist.o
kernelsu-objs := apk_sign.o
obj-y += kernelsu.o
obj-y += module_api.o
obj-y += sucompat.o
obj-y += uid_observer.o
obj-y += manager.o
obj-y += core_hook.o
obj-y += ksud.o
obj-y += embed_ksud.o
obj-y += kernel_compat.o

obj-y += selinux/
# .git is a text file while the module is imported by 'git submodule add'.
ifeq ($(shell test -e $(srctree)/$(src)/../.git; echo $$?),0)
# We must use the absolute path to git, otherwise the build will fail if git is not in the PATH
KSU_GIT_VERSION := $(shell cd $(srctree)/$(src);/usr/bin/git rev-list --count HEAD)
ccflags-y += -DKSU_GIT_VERSION=$(KSU_GIT_VERSION)
endif

# ĐÃ XÓA: Bỏ hoàn toàn cấu hình EXPECTED_SIZE và EXPECTED_HASH vì ta sẽ bypass trực tiếp trong code C

ccflags-y += -Wno-implicit-function-declaration -Wno-strict-prototypes -Wno-int-conversion -Wno-gcc-compat
ccflags-y += -Wno-macro-redefined -Wno-declaration-after-statement
