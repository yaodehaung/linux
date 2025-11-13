#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#define AF_MYPROTO 31   // 選擇一個未使用的 AF

/* 自訂 socket 內部資料 */
struct my_sock {
    struct sock sk;
    char buffer[256];
    size_t len;
};

/* sendmsg callback */
static int my_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
    struct my_sock *mysk = (struct my_sock *)sock->sk;
    if (len > sizeof(mysk->buffer))
        return -EINVAL;

    if (copy_from_user(mysk->buffer, msg->msg_iov->iov_base, len))
        return -EFAULT;

    mysk->len = len;
    pr_info("my_socket: sendmsg received %zu bytes\n", len);
    return len;
}

/* recvmsg callback */
static int my_recvmsg(struct socket *sock, struct msghdr *msg, size_t len,
                      int flags)
{
    struct my_sock *mysk = (struct my_sock *)sock->sk;
    size_t copy_len = mysk->len;

    if (copy_len > len)
        copy_len = len;

    if (copy_to_user(msg->msg_iov->iov_base, mysk->buffer, copy_len))
        return -EFAULT;

    pr_info("my_socket: recvmsg sending %zu bytes\n", copy_len);
    return copy_len;
}

/* release callback */
static int my_release(struct socket *sock)
{
    struct sock *sk = sock->sk;
    pr_info("my_socket: release socket\n");
    if (sk)
        sock_put(sk);
    return 0;
}

/* proto_ops 定義 */
static const struct proto_ops my_proto_ops = {
    .family = AF_MYPROTO,
    .owner = THIS_MODULE,
    .release = my_release,
    .sendmsg = my_sendmsg,
    .recvmsg = my_recvmsg,
};

/* proto 定義 */
static struct proto my_proto = {
    .name = "MY_PROTO",
    .owner = THIS_MODULE,
};

/* create callback */
static int my_socket_create(struct net *net, struct socket *sock, int protocol, int kern)
{
    struct sock *sk;
    sk = sk_alloc(net, AF_MYPROTO, GFP_KERNEL, &my_proto);
    if (!sk)
        return -ENOMEM;

    sock_init_data(sock, sk);
    sock->ops = &my_proto_ops;

    pr_info("my_socket: socket created\n");
    return 0;
}

/* proto_family 定義 */
static struct net_proto_family my_family = {
    .family = AF_MYPROTO,
    .create = my_socket_create,
    .owner = THIS_MODULE,
};

/* module init / exit */
static int __init my_socket_init(void)
{
    int ret;
    ret = sock_register(&my_family);
    if (ret)
        pr_err("my_socket: failed to register family\n");
    else
        pr_info("my_socket: module loaded\n");
    return ret;
}

static void __exit my_socket_exit(void)
{
    sock_unregister(AF_MYPROTO);
    pr_info("my_socket: module unloaded\n");
}

module_init(my_socket_init);
module_exit(my_socket_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nick Huang");
MODULE_DESCRIPTION("Example: custom kernel socket");

