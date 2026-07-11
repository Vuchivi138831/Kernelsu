#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/version.h>

#ifdef CONFIG_KSU_DEBUG
#include <linux/moduleparam.h>
#endif

#include "apk_sign.h"
#include "klog.h" // IWYU pragma: keep
#include "kernel_compat.h"

#ifdef CONFIG_KSU_DEBUG
int ksu_debug_manager_uid = -1;
#include "manager.h"

static int set_expected_size(const char *val, const struct kernel_param *kp)
{
	int rv = param_set_uint(val, kp);
	ksu_set_manager_uid(ksu_debug_manager_uid);
	pr_info("ksu_manager_uid set to %d\n", ksu_debug_manager_uid);
	return rv;
}

static struct kernel_param_ops expected_size_ops = {
	.set = set_expected_size,
	.get = param_get_uint,
};

module_param_cb(ksu_debug_manager_uid, &expected_size_ops,
		&ksu_debug_manager_uid, S_IRUSR | S_IWUSR);
#endif

/*
 * HÀM KIỂM TRA CHÍNH: Đã loại bỏ toàn bộ logic check APK.
 * Luôn trả về true để chấp nhận bất kỳ ứng dụng Manager nào.
 */
bool is_manager_apk(char *path)
{
#ifdef CONFIG_KSU_DEBUG
	pr_info("ksu_test: Bypass signature check for path: %s\n", path);
#endif
	return true;
}
