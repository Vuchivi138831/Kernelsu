#ifndef _KSU_H_
#define _KSU_H_

#include <linux/types.h>
#include <linux/fs.h>

// Tiền khai báo các cấu trúc dữ liệu của Kernel 4.9
struct linux_binprm;
struct file;
struct filename;

/**
 * ksu_handle_execve - Hook tại hàm tiến trình (fs/exec.c)
 * Phiên bản Kernel 4.9 sử dụng struct linux_binprm để quản lý dữ liệu thực thi
 */
extern void ksu_handle_execve(struct linux_binprm *bprm);

/**
 * ksu_handle_openat - Hook tại hàm mở file (fs/open.c)
 * @dfd: Thư mục chứa file cần mở (Directory file descriptor)
 * @filename: Cấu trúc chứa tên file trong kernel space (struct filename *)
 */
extern void ksu_handle_openat(int dfd, struct filename *filename, int flags, umode_t mode);

/**
 * ksu_handle_vfs_read - Hook tại hàm đọc file hệ thống (fs/read_write.c)
 * Ở Kernel 4.9, con trỏ vị trí tệp 'pos' là kiểu loff_t *
 */
extern void ksu_handle_vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos);

/**
 * ksu_handle_stat - Hook tại hàm lấy thông tin file (fs/stat.c)
 * Dùng để ẩn hoặc thay đổi thông tin các file liên quan đến KSU / Root
 */
extern void ksu_handle_stat(int dfd, struct filename *filename, int flag);

#endif /* _KSU_H_ */
