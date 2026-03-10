#include <asm/io.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>

typedef struct {
  unsigned long addr;
  void *uptr;
  unsigned long ulen;
} Payload;

static long teemo_ioctl(struct file *file, unsigned int cmd,
                        unsigned long arg) {
  Payload payload;
  if (copy_from_user(&payload, (const void *)arg, sizeof(Payload))) {
    return -EFAULT;
  }
  char buf[0x2000];
  unsigned long page = payload.addr & ~0xFFF;
  unsigned long offset = payload.addr & 0xFFF;
  if (payload.ulen > sizeof(buf)) {
    return -EINVAL;
  }
  if (offset + payload.ulen > 0x2000) {
    return -EINVAL;
  }

  long err = 0;
  void *mem = ioremap(page, 0x2000);
  if (mem == NULL) {
    err = -EPERM;
    goto out;
  }

  if (cmd == 1) {
    if (copy_from_user(&buf, payload.uptr, payload.ulen)) {
      err = -EFAULT;
      goto out;
    }

    memcpy(mem + offset, buf, payload.ulen);
  } else {
    memcpy(buf, mem + offset, payload.ulen);
    if (copy_to_user(payload.uptr, buf, payload.ulen)) {
      err = -EFAULT;
      goto out;
    }
  }

out:
  iounmap(mem);
  return err;
}

static struct file_operations teemo_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = teemo_ioctl,
};

static struct miscdevice teemo_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "teemo",
    .fops = &teemo_fops,
};

static int teemo_init(void) {
  misc_register(&teemo_device);
  return 0;
}

module_init(teemo_init);
MODULE_LICENSE("GPL");