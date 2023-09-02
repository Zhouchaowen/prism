// go:build ignore
#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"

#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_STOLEN 4
#define TC_ACT_REDIRECT 7

#define ETH_P_IP 0x0800 /* Internet Protocol packet        */

#define ETH_HLEN sizeof(struct ethhdr)
#define IP_HLEN sizeof(struct iphdr)
#define TCP_HLEN sizeof(struct tcphdr)
#define UDP_HLEN sizeof(struct udphdr)
#define DNS_HLEN sizeof(struct dns_hdr)

#define MAX_DATA_SIZE 4000
enum tc_type { Egress, Ingress };

struct http_data_event_t {
  enum tc_type type;
  char data[MAX_DATA_SIZE];
  int32_t data_len;
};

//struct
//{
//    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
//} tls_events SEC(".maps");

// BPF ringbuf map
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024 /* 256 KB */);
} tls_events SEC(".maps");


// BPF programs are limited to a 512-byte stack. We store this value per CPU
// and use it as a heap allocated value.
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct http_data_event_t);
    __uint(max_entries, 1);
} data_buffer_heap SEC(".maps");

/***********************************************************
 * General helper functions
 ***********************************************************/

// 数组拷贝
//static __inline void *memcpy(void *dest, const void *src, int32_t count) {
//  char *pdest = (char *)dest;
//  const char *psrc = (const char *)src;
//  if (psrc > pdest || pdest >= psrc + count) {
//    while (count--)
//      *pdest++ = *psrc++;
//  } else {
//    while (count--)
//      *(pdest + count) = *(psrc + count);
//  }
//  return dest;
//}

static __inline struct http_data_event_t* create_http_data_event() {
  uint32_t kZero = 0;
  struct http_data_event_t* event = bpf_map_lookup_elem(&data_buffer_heap, &kZero);
  if (event == NULL) {
    return NULL;
  }

  return event;
}

static __inline int capture_packets(struct __sk_buff *skb,enum tc_type type) {
    bpf_skb_pull_data(skb, skb->len);
    // Packet data
    void *data_start = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // 边界检查：检查数据包是否大于完整以太网 + IP 报头
    if (data_start + ETH_HLEN + IP_HLEN + TCP_HLEN > data_end) {
        return TC_ACT_OK;
    }

    // Ethernet headers
    struct ethhdr *eth = (struct ethhdr *)data_start;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    // IP headers
    struct iphdr *iph = (struct iphdr *)(data_start + ETH_HLEN);
    if (iph->protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

    int len = (int)(data_end-data_start);
    bpf_printk("len: %d\n",len);
    if (len < 0) {
        return TC_ACT_OK;
    }

    // 理论上这是一个http包的最小报文大小
    if (len <= 91){
        bpf_printk("---------no http---------\n");
        return TC_ACT_OK;
    }

    struct http_data_event_t* event = create_http_data_event();
    if (event == NULL) {
      return TC_ACT_OK;
    }

    event = bpf_ringbuf_reserve(&tls_events, sizeof(struct http_data_event_t), 0);
    if (!event) {
        bpf_printk("---------no memory---------\n");
        return 0;
    }

    event->type = type;
    // This is a max function, but it is written in such a way to keep older BPF verifiers happy.
    event->data_len = (len < MAX_DATA_SIZE ? len : MAX_DATA_SIZE);
//    event->data_len = 100;
    bpf_printk("event->data_len: %d\n",event->data_len);
    bpf_printk("event->data: %d\n",sizeof(event->data));
//    memcpy(event->data, data_start, event->data_len);
    void *cursor = (void *)(long)skb->data;
    int name_pos = 0;
    for (int i = 0; i < 4000; i++) {
        // 游标的边界检查。验证者在此处需要 +1。
        // 可能是因为我们在循环结束时推进了指针
        if (cursor + 1 > data_end) {
          bpf_printk("Error: break");
          break;
        }

        event->data[name_pos] = *(char *)(cursor);
        cursor++;
        name_pos++;
    }


//    bpf_perf_event_output(skb, &tls_events, BPF_F_CURRENT_CPU, event,sizeof(struct http_data_event_t));
    bpf_ringbuf_submit(event, 0);

    return TC_ACT_OK;
}

// egress_cls_func is called for packets that are going out of the network
SEC("classifier/egress")
int egress_cls_func(struct __sk_buff *skb) { return capture_packets(skb,Egress); }

// ingress_cls_func is called for packets that are coming into the network
SEC("classifier/ingress")
int ingress_cls_func(struct __sk_buff *skb) { return capture_packets(skb,Ingress); }

char _license[] SEC("license") = "GPL";
