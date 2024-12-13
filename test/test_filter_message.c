#include <linux/netlink.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <usermsg.h>

#define NETLINK_USER 31
#define MAX_MSG_SIZE 256

void test_filter_msg(int sock_fd, struct sockaddr_nl *dest_addr, struct filter_msg *f_msg, size_t msg_size) {
    struct nlmsghdr *nlh;
    struct iovec iov[1];
    struct msghdr msg;

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_MSG_SIZE));
    if (!nlh) {
        perror("malloc failed");
        return;
    }
    memset(nlh, 0, NLMSG_SPACE(MAX_MSG_SIZE));
    nlh->nlmsg_len = NLMSG_LENGTH(msg_size);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    memcpy(NLMSG_DATA(nlh), f_msg, msg_size);

    iov[0].iov_base = (void *)nlh;
    iov[0].iov_len = nlh->nlmsg_len;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)dest_addr;
    msg.msg_namelen = sizeof(*dest_addr);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    if (sendmsg(sock_fd, &msg, 0) < 0) {
        perror("sendmsg failed");
    } else {
        printf("message sent to kernel, action %d\n", f_msg->action);
    }

    free(nlh);
}

int main() {
    int sock_fd;
    struct sockaddr_nl src_addr, dest_addr;
    struct filter_msg f_msg;

    sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (sock_fd < 0) {
        perror("socket");
        return -1;
    }

    int buf_size = 65536;
    setsockopt(sock_fd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
    setsockopt(sock_fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();

    if (bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
        perror("bind");
        return -1;
    }

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;

    //test 1 block destination ip
    memset(&f_msg, 0, sizeof(f_msg));
    f_msg.action = BLOCK_IP_DEST;
    inet_pton(AF_INET, "192.168.0.100", &f_msg.ip_addr);
    test_filter_msg(sock_fd, &dest_addr, &f_msg, sizeof(f_msg));

    //test 2 block source ip
    memset(&f_msg, 0, sizeof(f_msg));
    f_msg.action = BLOCK_IP_SRC;
    inet_pton(AF_INET, "192.168.0.50", &f_msg.ip_addr);
    test_filter_msg(sock_fd, &dest_addr, &f_msg, sizeof(f_msg));

    //test 3 block tcp protocol
    memset(&f_msg, 0, sizeof(f_msg));
    f_msg.action = BLOCK_PROTOCOL;
    f_msg.protocol = IPPROTO_TCP;
    test_filter_msg(sock_fd, &dest_addr, &f_msg, sizeof(f_msg));

    //test 4 block port for incoming
    memset(&f_msg, 0, sizeof(f_msg));
    f_msg.action = BLOCK_PORT;
    f_msg.p_rule.port = 80;
    f_msg.p_rule.direction = BLOCK_PORT_INCOMING;
    f_msg.p_rule.protocol = IPPROTO_TCP;
    test_filter_msg(sock_fd, &dest_addr, &f_msg, sizeof(f_msg));

    //test 5 block port for outgoing
    memset(&f_msg, 0, sizeof(f_msg));
    f_msg.action = BLOCK_PORT;
    f_msg.p_rule.port = 53;
    f_msg.p_rule.direction = BLOCK_PORT_OUTGOING;
    f_msg.p_rule.protocol = IPPROTO_UDP;
    test_filter_msg(sock_fd, &dest_addr, &f_msg, sizeof(f_msg));

    //test 6 block port both
    memset(&f_msg, 0, sizeof(f_msg));
    f_msg.action = BLOCK_PORT;
    f_msg.p_rule.port = 22;
    f_msg.p_rule.direction = BLOCK_PORT_BOTH;
    f_msg.p_rule.protocol = IPPROTO_TCP;
    test_filter_msg(sock_fd, &dest_addr, &f_msg, sizeof(f_msg));

    close(sock_fd);
    return 0;
}