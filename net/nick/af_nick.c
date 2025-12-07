#include <linux/bpf-cgroup.h>
#include <linux/uaccess.h>
#include <asm/ioctls.h>
#include <linux/memblock.h>
#include <linux/highmem.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/module.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/igmp.h>
#include <linux/inetdevice.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/mm.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <linux/sock_diag.h>
#include <net/tcp_states.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <net/net_namespace.h>
#include <net/icmp.h>
#include <net/inet_hashtables.h>
#include <net/ip.h>
#include <net/ip_tunnels.h>
#include <net/route.h>
#include <net/checksum.h>
#include <net/gso.h>
#include <net/xfrm.h>
#include <trace/events/udp.h>
#include <linux/static_key.h>


#define AF_MYPROTO 46   // 自訂 protocol number
struct proto;  // 前向宣告 (incomplete type)

/* ---- 定義 proto_ops ---- */
static int my_proto_connect(struct socket *sock, struct sockaddr *addr, int addr_len, int flags)
{
    return 0;
}

static int my_proto_release(struct socket *sock)
{
    return 0;
}

static const struct proto_ops my_proto_ops = {
    .family = AF_MYPROTO,
    .connect = my_proto_connect,
    .release = my_proto_release,
    // 其他 callback 可以 NULL 或自訂
};

/* ---- 定義 proto ---- */
static struct proto my_proto = {
    .name = "MYPROTO",         // 必須是合法 kernel 字串
    .owner = THIS_MODULE,
    .obj_size = sizeof(struct sock),
};

/* ---- 定義 net_proto_family ---- */
static int my_family_create(struct net *net, struct socket *sock, int protocol, int kern)
{
    sock->ops = &my_proto_ops;   // 指派 proto_ops
    sock->sk = sk_alloc(net, AF_MYPROTO, GFP_KERNEL, &my_proto, kern);
    if (!sock->sk)
        return -ENOMEM;

    printk(KERN_INFO "my_family_create called\n");
    return 0;
}

static struct net_proto_family my_family = {
    .family = AF_MYPROTO,
    .create = my_family_create,
    .owner  = THIS_MODULE,
};

/* ---- module init / exit ---- */
static int __init af_nick_init(void)
{
    int ret;

    printk(KERN_INFO "af_nick module init\n");

    ret = proto_register(&my_proto, 1);  // 註冊 proto
    if (ret < 0) {
        printk(KERN_ERR "proto_register failed: %d\n", ret);
        sock_unregister(AF_MYPROTO);
        return ret;
    }

    ret = sock_register(&my_family);
    if (ret < 0) {
        printk(KERN_ERR "sock_register failed: %d\n", ret);
        return ret;
    }


    printk(KERN_INFO "af_nick module loaded successfully\n");
    return 0;
}

static void __exit af_nick_exit(void)
{
    proto_unregister(&my_proto);
    sock_unregister(AF_MYPROTO);
    printk(KERN_INFO "af_nick module unloaded\n");
}

module_init(af_nick_init);
module_exit(af_nick_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nick Huang");
MODULE_DESCRIPTION("AF_MYPROTO (46) example module");

