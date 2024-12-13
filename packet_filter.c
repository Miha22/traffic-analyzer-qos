
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/string.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/inet.h> 
#include <netlink/genl/genl.h>

#include <usermsg.h>

#define NETLINK_USER 31
#define MAX_MSG_SIZE 256
#define MAX_FILTER_IPS 100

static uint32_t block_src_ips[MAX_FILTER_IPS];
static uint32_t block_dest_ips[MAX_FILTER_IPS];
static int block_src_count = 0;
static int block_dest_count = 0;

static struct sock *nl_sk = NULL;
static struct nf_hook_ops nfho;

static int add_src2blacklist(const char *ip_str) {
    if (block_src_count >= MAX_FILTER_IPS) {
        printk(KERN_ERR "source IP block list is full\n");
        return -ENOMEM;
    }
    block_src_ips[block_src_count++] = ip_bin;
    printk(KERN_INFO "added source IP to block list: %pI4\n", &ip_bin);
    return 0;
}

static int add_dest2blacklist(const char *ip_str) {
    if (block_dest_count >= MAX_FILTER_IPS) {
        printk(KERN_ERR "destination IP block list is full\n");
        return -ENOMEM;
    }
    block_dest_ips[block_dest_count++] = ip_bin;
    printk(KERN_INFO "added destination IP to block list: %pI4\n", &ip_bin);
    return 0;
}

static void netlink_recv_msg(struct sk_buff *skb) {
    struct nlmsghdr *nlh;
    struct filter_msg *msg;

    nlh = (struct nlmsghdr *)skb->data;
    msg = (struct filter_msg *)NLMSG_DATA(nlh);

    if (nlh->nlmsg_len > MAX_MSG_SIZE) {
        printk(KERN_ERR "received message is too large: %d\n", nlh->nlmsg_len);
        return;
    }

    switch (msg->action) {
        case BLOCK_IP_SRC:
            printk(KERN_INFO "Blocking packets from source IP: %s\n", msg->ip_addr);
            add_src2blacklist(msg->ip_addr);
        break;
        case BLOCK_IP_DEST:
            printk(KERN_INFO "Blocking packets to destination IP: %s\n", msg->ip_addr);
            add_des2blacklist(msg->ip_addr);
        break;
        case BLOCK_PROTOCOL:
            printk(KERN_INFO "Blocking packets of protocol IP: %s\n", msg->protocol);

        break;
        case BLOCK_PORT:
            printk(KERN_INFO "Blocking packets to/from PORT: %s\n", msg->port);

        break;
        default:
            printk(KERN_WARNING "Unknown action received\n");
            break;
    }

}

static unsigned int packet_capture(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph;
    struct udphdr *udph;

    if (iph) {
        printk(KERN_INFO "packet captured: src=%pI4, dest=%pI4, protocol=%u\n",
               &iph->saddr, &iph->daddr, iph->protocol);

        if (iph->protocol == IPPROTO_TCP) {
            tcph = tcp_hdr(skb);
            printk(KERN_INFO "TCP Packet: src port=%u, dest port=%u\n",
                   ntohs(tcph->source), ntohs(tcph->dest));
        } else if (iph->protocol == IPPROTO_UDP) {
            udph = udp_hdr(skb);
            printk(KERN_INFO "UDP Packet: src port=%u, dest port=%u\n",
                   ntohs(udph->source), ntohs(udph->dest));
        }
    }
    return NF_ACCEPT;
}

static int netlink_init(void) {
    struct netlink_kernel_cfg cfg = {
        .input = netlink_recv_msg,
    };

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if (!nl_sk) {
        printk(KERN_ALERT "Failed to create Netlink socket\n");
        return -ENOMEM;
    }
    printk(KERN_INFO "Netlink socket created\n");
    return 0;
}

static int __init packetfilter_init(void) {
    int ret = netlink_init();
    if (ret)
        return ret;

    nfho.hook = packet_capture;
    nfho.pf = NFPROTO_IPV4;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho);
    printk(KERN_INFO "Netfilter module loaded.\n");

    return 0;
}

static void __exit packetfilter_exit(void) {
    netlink_kernel_release(nl_sk);
    nf_unregister_net_hook(&init_net, &nfho);
    printk(KERN_INFO "Netfilter module unloaded.\n");
}

module_init(packetfilter_init);
module_exit(packetfilter_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Den");
MODULE_DESCRIPTION("Netfilter Module");