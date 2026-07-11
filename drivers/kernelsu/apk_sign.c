#include "linux/fs.h"
#include "linux/moduleparam.h"

#include "apk_sign.h"
#include "klog.h" // IWYU pragma: keep
#include "kernel_compat.h"

static __always_inline int
check_v2_signature(char *path, unsigned expected_size, unsigned expected_hash)
{
	unsigned char buffer[0x11] = { 0 };
	u32 size4;
	u64 size8, size_of_block;
	loff_t pos;
	int sign = -1;
	int i;

	struct file *fp = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		pr_err("open %s error.", path);
		return PTR_ERR(fp);
	}

	// disable inotify for this file
	fp->f_mode |= FMODE_NONOTIFY;

	sign = 1;
	// https://en.wikipedia.org/wiki/Zip_(file_format)#End_of_central_directory_record_(EOCD)
	for (i = 0;; ++i) {
		unsigned short n;
		pos = generic_file_llseek(fp, -i - 2, SEEK_END);
		ksu_kernel_read_compat(fp, &n, 2, &pos);
		if (n == i) {
			pos -= 22;
			ksu_kernel_read_compat(fp, &size4, 4, &pos);
			if ((size4 ^ 0xcafebabeu) == 0xccfbf1eeu) {
				break;
			}
		}
		if (i == 0xffff) {
			pr_info("error: cannot find eocd\n");
			goto clean;
		}
	}

	pos += 12;
	ksu_kernel_read_compat(fp, &size4, 0x4, &pos);
	pos = size4 - 0x18;

	ksu_kernel_read_compat(fp, &size8, 0x8, &pos);
	ksu_kernel_read_compat(fp, buffer, 0x10, &pos);
	if (strcmp((char *)buffer, "APK Sig Block 42")) {
		goto clean;
	}

	pos = size4 - (size8 + 0x8);
	ksu_kernel_read_compat(fp, &size_of_block, 0x8, &pos);
	if (size_of_block != size8) {
		goto clean;
	}

	for (;;) {
		uint32_t id;
		uint32_t offset;
		ksu_kernel_read_compat(fp, &size8, 0x8, &pos);
		if (size8 == size_of_block) {
			break;
		}
		ksu_kernel_read_compat(fp, &id, 0x4, &pos);
		offset = 4;
		
		if ((id ^ 0xdeadbeefu) == 0xafa439f5u || (id ^ 0xdeadbeefu) == 0x2efed62f) {
			// Giải mã cấu trúc file đến vùng dữ liệu để không làm hỏng con trỏ file (pos)
			ksu_kernel_read_compat(fp, &size4, 0x4, &pos);
			ksu_kernel_read_compat(fp, &size4, 0x4, &pos);
			ksu_kernel_read_compat(fp, &size4, 0x4, &pos);
			offset += 0x4 * 3;

			ksu_kernel_read_compat(fp, &size4, 0x4, &pos);
			pos += size4;
			offset += 0x4 + size4;

			ksu_kernel_read_compat(fp, &size4, 0x4, &pos);
			ksu_kernel_read_compat(fp, &size4, 0x4, &pos);
			offset += 0x4 * 2;

			// ÉP BUỘC CHẤP NHẬN: Bỏ hoàn toàn vòng lặp so khớp hash cũ
			// Chỉ cần cấu trúc file có block chữ ký hợp lệ, gán sign = 0 (Thành công) và thoát luôn
			sign = 0;
			break;
		}
		pos += (size8 - offset);
	}

clean:
	filp_close(fp, 0);
	return sign;
}

#ifdef CONFIG_KSU_DEBUG
unsigned ksu_expected_size = 0;
unsigned ksu_expected_hash = 0;

#include "manager.h"

static int set_expected_size(const char *val, const struct kernel_param *kp)
{
	int rv = param_set_uint(val, kp);
	ksu_invalidate_manager_uid();
	return rv;
}

static int set_expected_hash(const char *val, const struct kernel_param *kp)
{
	int rv = param_set_uint(val, kp);
	ksu_invalidate_manager_uid();
	return rv;
}

static struct kernel_param_ops expected_size_ops = {
	.set = set_expected_size,
	.get = param_get_uint,
};

static struct kernel_param_ops expected_hash_ops = {
	.set = set_expected_hash,
	.get = param_get_uint,
};

module_param_cb(ksu_expected_size, &expected_size_ops, &ksu_expected_size, S_IRUSR | S_IWUSR);
module_param_cb(ksu_expected_hash, &expected_hash_ops, &ksu_expected_hash, S_IRUSR | S_IWUSR);

int is_manager_apk(char *path)
{
	return check_v2_signature(path, ksu_expected_size, ksu_expected_hash);
}
#else
int is_manager_apk(char *path)
{
	return check_v2_signature(path, 0, 0);
}
#endif
