#define MAX_DNS_NAME_LENGTH 256

struct eth_hdr {
  unsigned char h_dest[6];
  unsigned char h_source[6];
  __u16 h_proto;
};

struct ip_hdr {
  __u8 ihl : 4;
  __u8 version : 4;
  __u8 tos;
  __u16 tot_len;
  __u16 id;
  __u16 frag_off;
  __u8 ttl;
  __u8 protocol;
  __sum16 check;
  __u32 s_addr;
  __u32 d_addr;
};

struct udp_hdr {
  __u16 source; // 源端口号（16 位），网络字节序；
  __u16 dest;   // 目的端口号（16 位），网络字节序；
  __u16 len;    // UDP 数据包的长度（16 位），包括 UDP 头部和数据部分的长度，网络字节序；
  __u16 check;  // 校验和（16 位），网络字节序。
};

struct dns_hdr {
  __u16 transaction_id;
  __u8 rd : 1;      // Recursion desired
  __u8 tc : 1;      // Truncated
  __u8 aa : 1;      // Authoritive answer
  __u8 opcode : 4;  // Opcode
  __u8 qr : 1;      // Query/response flag
  __u8 r_code : 4;  // Response code
  __u8 cd : 1;      // Checking disabled
  __u8 ad : 1;      // Authenticated data
  __u8 z : 1;       // Z reserved bit
  __u8 ra : 1;      // Recursion available
  __u16 q_count;    // Number of questions
  __u16 ans_count;  // Number of answer RRs
  __u16 auth_count; // Number of authority RRs
  __u16 add_count;  // Number of resource RRs
};
