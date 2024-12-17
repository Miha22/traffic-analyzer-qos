
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
#include <usermsg.h>
#include <packet_filter.h>

#define NETLINK_USER 31
#define MAX_MSG_SIZE 256
#define MAX_PROTOCOL_RULES 50
#define MAX_FILTER_IPS 100
#define MAX_PORT_RULES 200

static uint8_t blocked_protocols[MAX_PROTOCOL_RULES];
static struct port_rule blocked_ports[MAX_PORT_RULES];
static struct in_addr block_src_ips[MAX_FILTER_IPS];
static struct in_addr block_dest_ips[MAX_FILTER_IPS];

static int block_protocol_count = 0;
static int block_ports_count = 0;
static int block_src_count = 0;
static int block_dest_count = 0;

static struct sock *nl_sk = NULL;
static struct nf_hook_ops nfho;

static int add_src2blacklist(struct in_addr *ip_bin) {
    if (block_src_count >= MAX_FILTER_IPS) {
        printk(KERN_ERR "source IP block list is full\n");
        return -ENOMEM;
    }
    block_src_ips[block_src_count++] = *ip_bin;
    printk(KERN_INFO "added source IP to block list: %pI4\n", &ip_bin->s_addr);
    return 0;
}

static int add_dest2blacklist(struct in_addr *ip_bin) {
    if (block_dest_count >= MAX_FILTER_IPS) {
        printk(KERN_ERR "destination IP block list is full\n");
        return -ENOMEM;
    }
    block_dest_ips[block_dest_count++] = *ip_bin;
    printk(KERN_INFO "added destination IP to block list: %pI4\n", &ip_bin->s_addr);
    return 0;
}

static int add_port2blacklist(uint16_t port, uint8_t direction, uint8_t protocol) {
    if (block_ports_count >= MAX_PORT_RULES) {
        printk(KERN_ERR "port block list is full\n");
        return -ENOMEM;
    }
    blocked_ports[block_ports_count].port = port;
    blocked_ports[block_ports_count].direction = direction;
    blocked_ports[block_ports_count].protocol = protocol;
    block_ports_count++;
    printk(KERN_INFO "added port '%u' to block list direction: %d protocol: %u\n", port, direction, protocol);
    
    return 0;
}

static int add_protocol2blacklist(uint8_t protocol) {
    if (block_protocol_count >= MAX_FILTER_IPS) {
        printk(KERN_ERR "protocol block list is full\n");
        return -ENOMEM;
    }
    blocked_protocols[block_protocol_count++] = protocol;
    printk(KERN_INFO "added protocol %u to block list\n", protocol);
    return 0;
}

static void process_filter_msg(struct filter_msg *msg) {
    switch (msg->action) {
        case BLOCK_IP_SRC:
            printk(KERN_INFO "processing BLOCK_IP_SRC for IP: %pI4\n", &msg->ip_addr.s_addr);
            add_src2blacklist(&msg->ip_addr);
            break;

        case BLOCK_IP_DEST:
            printk(KERN_INFO "processing BLOCK_IP_DEST for IP: %pI4\n", &msg->ip_addr.s_addr);
            add_dest2blacklist(&msg->ip_addr);
            break;

        case BLOCK_PORT:
            printk(KERN_INFO "processing BLOCK_PORT: port=%u, direction=%d, protocol=%u\n",
                   msg->p_rule.port, msg->p_rule.direction, msg->p_rule.protocol);
            add_port2blacklist(msg->p_rule.port, msg->p_rule.direction, msg->p_rule.protocol);
            break;

        case BLOCK_PROTOCOL:
            printk(KERN_INFO "processing BLOCK_PROTOCOL: protocol=%u\n", msg->protocol);
            add_protocol2blacklist(msg->protocol);
            break;

        default:
            printk(KERN_WARNING "unknown action: %d\n", msg->action);
            break;
    }
}

static void netlink_recv_msg(struct sk_buff *skb) {
    struct nlmsghdr *nlh;
    struct filter_msg *msg;

    nlh = (struct nlmsghdr *)skb->data;
    msg = (struct filter_msg *)NLMSG_DATA(nlh);

    if (nlh->nlmsg_len < NLMSG_SPACE(sizeof(struct filter_msg)) || nlh->nlmsg_len > MAX_MSG_SIZE) {
        printk(KERN_ERR "received message is too large: %d\n", nlh->nlmsg_len);
        return;
    }


    process_filter_msg(msg);
}

static unsigned int packet_capture(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph;
    struct udphdr *udph;
    int i;

    if(!iph) {
        printk(KERN_INFO "IP header of skull buffer is empty\n");
        return NF_ACCEPT;
    }
        
    for (i = 0; i < block_src_count; i++) {
        if (iph->saddr == block_src_ips[i].s_addr) {
            printk(KERN_INFO "Dropped packet from blocked source IP: %pI4\n", &iph->saddr);
            return NF_DROP;
        }
    }

    for (i = 0; i < block_dest_count; i++) {
        if (iph->daddr == block_dest_ips[i].s_addr) {
            printk(KERN_INFO "Dropped packet to blocked destination IP: %pI4\n", &iph->daddr);
            return NF_DROP;
        }
    }

    for (i = 0; i < block_protocol_count; i++) {
        if (iph->protocol == blocked_protocols[i]) {
            printk(KERN_INFO "Dropped packet of blocked protocol: %u\n", iph->protocol);
            return NF_DROP;
        }
    }

    if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
        if (iph->protocol == IPPROTO_TCP) {
            tcph = tcp_hdr(skb);
            for (i = 0; i < block_ports_count; i++) {
                if (blocked_ports[i].protocol == IPPROTO_TCP &&
                    ((blocked_ports[i].direction == BLOCK_PORT_INCOMING && ntohs(tcph->dest) == blocked_ports[i].port) ||
                        (blocked_ports[i].direction == BLOCK_PORT_OUTGOING && ntohs(tcph->source) == blocked_ports[i].port) ||
                        (blocked_ports[i].direction == BLOCK_PORT_BOTH &&
                        (ntohs(tcph->source) == blocked_ports[i].port || ntohs(tcph->dest) == blocked_ports[i].port)))) {
                    printk(KERN_INFO "Dropped TCP packet on port %u, direction %d\n",
                            blocked_ports[i].port, blocked_ports[i].direction);
                    return NF_DROP;
                }
            }
        } 
        else if (iph->protocol == IPPROTO_UDP) {
            udph = udp_hdr(skb);
            for (i = 0; i < block_ports_count; i++) {
                if (blocked_ports[i].protocol == IPPROTO_UDP &&
                    ((blocked_ports[i].direction == BLOCK_PORT_INCOMING && ntohs(udph->dest) == blocked_ports[i].port) ||
                        (blocked_ports[i].direction == BLOCK_PORT_OUTGOING && ntohs(udph->source) == blocked_ports[i].port) ||
                        (blocked_ports[i].direction == BLOCK_PORT_BOTH &&
                        (ntohs(udph->source) == blocked_ports[i].port || ntohs(udph->dest) == blocked_ports[i].port)))) {
                    printk(KERN_INFO "Dropped UDP packet on port %u, direction %d\n",
                            blocked_ports[i].port, blocked_ports[i].direction);
                    return NF_DROP;
                }
            }
        }
    }

    printk(KERN_INFO "Packet accepted: src=%pI4, dest=%pI4, protocol=%u\n", &iph->saddr, &iph->daddr, iph->protocol);

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