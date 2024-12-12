#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/init.h>
#include <linux/ip.h>

static struct nf_hook_ops nfho;

static unsigned int packet_capture(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph = ip_hdr(skb);
    if (iph) {
        printk(KERN_INFO "Packet captured: src=%pI4, dest=%pI4\n", &iph->saddr, &iph->daddr);
    }
    return NF_ACCEPT;
}

static int __init packetfilter_init(void) {
    nfho.hook = packet_capture;
    nfho.pf = NFPROTO_IPV4;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho);
    printk(KERN_INFO "Netfilter module loaded.\n");
    
    return 0;
}

static void __exit packetfilter_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
    printk(KERN_INFO "Netfilter module unloaded.\n");
}

module_init(packetfilter_init);
module_exit(packetfilter_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Den");
MODULE_DESCRIPTION("Netfilter Module");
