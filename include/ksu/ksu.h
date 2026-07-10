#ifndef _KSU_H_
#define _KSU_H_

#include <linux/types.h>
#include <linux/fs.h>

// Tiền khai báo các cấu trúc hệ thống của Kernel 4.9
struct linux_binprm;
struct file;
struct filename;

/**
 * ksu_handle_execve - Hook tại fs/exec.c
 * Nhận struct linux_binprm quản lý thông tin tiến trình thực thi
 */
extern void ksu_handle_execve(struct linux_binprm *bprm);

/**
 * ksu_handle_openat - Hook tại fs/open.c
 * Nhận biến 'tmp' là kiểu struct filename * sau khi qua getname()
 */
extern void ksu_handle_openat(int dfd, struct filename *filename, int flags, umode_t mode);

/**
 * ksu_handle_vfs_read - Hook tại fs/read_write.c
 * Nhận con trỏ vị trí tệp loff_t *pos của Kernel 4.9
 */
extern void ksu_handle_vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos);

/**
 * ksu_handle_stat - Hook tại fs/stat.c
 * Nhận biến 'name' kiểu struct filename * sau khi qua getname_flags()
 */
extern void ksu_handle_stat(int dfd, struct filename *filename, int flag);

#endif /* _KSU_H_ */
