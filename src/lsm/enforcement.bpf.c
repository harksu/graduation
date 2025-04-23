#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_map_structs.h"

#define AF_INET 2    // IPv4
#define AF_INET6 10  // IPv6


#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define FMODE_EXEC (1 << 18)
// file mode flag  

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef __constant_htons
#define __constant_htons(x) ((__u16)((((x) & 0xff) << 8) | (((x) >> 8) & 0xff)))
#endif

char LICENSE[] SEC("license") = "GPL";

static __always_inline event *reserve_and_init_event(void){
    //이벤트 초기화 함수
    event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return NULL;
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return NULL;
    }
    return e;
}

static __always_inline void process_event_handler(event *e, __u32 flags){
    //이벤트 링버퍼 전송 핸들러
    if (flags & POLICY_AUDIT)
        bpf_ringbuf_submit(e, 0);
    else
        bpf_ringbuf_discard(e, 0);
}

static __always_inline int file_delete_syscall_handler(struct path *path) {
    //파일 및 폴더 삭제 핸들러 
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!should_monitor(task))
        return 0;
    
    event *e = reserve_and_init_event();
    if (!e)
        return 0;
    
    if (bpf_d_path(path, e->data.path, sizeof(e->data.path)) < 0)
        bpf_printk("Failed to get file path");
    
    __u32 flags = match_policy(task, POLICY_FILE, e->data.path);
    if (!flags) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    
    int ret = 0;
    if (flags & POLICY_FILE_DELETE)
        ret = -1;
    
    bpf_printk("Operation not permitted at %s by policy \n", e->data.path);
    e->retval = ret;

    process_event_handler(e,flags);

    return ret;
}

static __always_inline __u32 normalize_f_flags(__u32 flags) {
    return flags & ~0x20;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_check_security, struct linux_binprm *bprm)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!should_monitor(task))
        return 0;

    event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Failed ringbuf_reserve");
        return 0;
    }

    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    if (bpf_d_path(&bprm->file->f_path, e->data.path, sizeof(e->data.path)) < 0) {
        //여기서 출력문 나중에 한 번 찍어보기
    }

    get_process_path(e->data.source, sizeof(e->data.source));

    e->event_id = SECID_BPRM_CHECK_SECURITY;
    e->retval = 0;

    __u32 flags = match_policy(task, POLICY_PROCESS, e->comm);

    if ((flags & POLICY_PROC_EXEC) || (flags & POLICY_FILE_EXEC)) {
        e->retval = -1;
        ret = e->retval;
    }
    process_event_handler(e,flags);
    return ret;
}

SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file)
{
    //미완성 => cat, ls {file_name}해야됨 => 해당 문제는 recursive_flag가 필요함(파일 전체 이름이 경로로 인자가 들어가지만, 정책은 경로만 인자로 넣기 때문에)
    //__u32 pid_ns_id;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    if(!should_monitor(task)) return 0;

    //pid_ns_id = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
    //bpf_printk("file_open_bpf: pid_ns_id=%u\n", pid_ns_id);

	event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Failed ringbuf_reserve");
        return 0;
    }    
    
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    
    if(bpf_d_path(&file->f_path, e->data.path, sizeof(e->data.path)) < 0){
        bpf_printk("Failed to get file path");
    }

    get_process_path(e->data.source, sizeof(e->data.source));

    __u32 flags = match_policy(task, POLICY_FILE, e->data.path);


    ret = 0;

    if ((flags & POLICY_FILE_READ) && ((file->f_flags & O_WRONLY) == 0))  {
        bpf_printk("block read at %s %d \n", e->data.path, flags);
        ret = -1;
    }
    // if ((!flags) && (file->f_flags & (O_WRONLY | O_RDWR))) {
    //     bpf_printk("block write at %s %d \n", e->data.path, flags);
    //     ret -= 1;
    // }
    if((flags & POLICY_FILE_WRITE) && (file->f_flags & (O_WRONLY | O_RDWR))) {
        bpf_printk("block write at %s %d \n", e->data.path, flags);
        ret = -1;
    }
    if ((flags & POLICY_FILE_EXEC) && (file->f_flags & FMODE_EXEC)) {
        bpf_printk("block execute at %s %d \n", e->data.path, flags);
        ret = -1;
    }

    
    e->event_id = SECID_FILE_OPEN;
    e->retval = ret; 
    
    process_event_handler(e,flags);
    
    return ret;
    //일단은 다 차단하는걸로
}

SEC("lsm/inode_create")
//파일 이름 기반으로 차단, 파일이름만을 경로로 설정하면 모두 적용이 됨 ex. test
int BPF_PROG(inode_create, struct inode *dir, struct dentry *dentry, umode_t mode) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    if (!should_monitor(task)) {
        return 0;
    }

    event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Failed ringbuf_reserve");
        return 0;
    }
    e->event_id = SECID_FILE_CREATE;

    char file_name[256] = {0};

    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    // if (bpf_probe_read_kernel_str(file_name, sizeof(file_name), dentry->d_name.name) < 0) {
    //     bpf_ringbuf_discard(e, 0);
    //     return 0;
    // }

    __u32 flags = match_policy(task, POLICY_FILE, file_name);


    if (flags & POLICY_FILE_CREATE) ret = -1;

    process_event_handler(e,flags);

    return ret;
}

SEC("lsm/path_mkdir")
int BPF_PROG(path_mkdir, struct path *path, umode_t mode)
{

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    if (!should_monitor(task)) {
        return 0;
    }

    event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Failed ringbuf_reserve");
        return 0;
    }    
    
    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    if (bpf_d_path(path, e->data.path, sizeof(e->data.path)) < 0) {
        bpf_printk("Failed to get file path");
    }

    __u32 flags = match_policy(task, POLICY_FILE, e->data.path);


    if (flags & POLICY_FILE_APPEND) {
        ret = -1;
        bpf_printk("Operation not permitted at %s by policy \n",e->data.path);
    }

    e->event_id = SECID_PATH_MKDIR;
    e->retval = ret; 

    process_event_handler(e,flags);

    return ret;
    //일단은 단순하게 플래그 있으면 차단으로
}

SEC("lsm/path_unlink")
int BPF_PROG(path_unlink, struct path *path)
{
   return file_delete_syscall_handler(path);
}

SEC("lsm/path_rmdir")
int BPF_PROG(path_rmdir, struct path *path)
{
   return file_delete_syscall_handler(path);

}

SEC("lsm/path_chmod")
int BPF_PROG(path_chmod, struct path *path, umode_t mode)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!should_monitor(task))
        return 0;

    event *e = reserve_and_init_event();
    if (!e)
        return 0;

    int ret = init_context(e);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    if (bpf_d_path(path, e->data.path, sizeof(e->data.path)) < 0)
        bpf_printk("Failed to get file path in path_chmod");

    get_process_path(e->data.source, sizeof(e->data.source));

    __u32 flags = match_policy(task, POLICY_FILE, e->data.path);
    if (flags & POLICY_FILE_SET_UID)
        ret = -1;
    else
        ret = 0;

    e->event_id = SECID_PATH_CHMOD;
    e->retval = ret;

    process_event_handler(e, flags);
    return ret;
}


// =========================
// XDP DDoS Defense 코드
// =========================

#define TCP_SYN_THRESHOLD 30
#define UDP_THRESHOLD     30

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
   // __u16 src_port;
   // __u16 dst_port;
    __u8  proto;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct flow_key);
    __type(value, __u32);
} flow_count SEC(".maps");

static __always_inline int parse_eth(void **data, void **data_end, struct ethhdr **ethhdr)
{
    *ethhdr = *data;
    if ((void*)(*ethhdr + 1) > *data_end)
        return -1;
    return 0;
}

static __always_inline int parse_ip(void **data, void **data_end, struct iphdr **iphdr)
{
    *iphdr = *data;
    if ((void*)(*iphdr + 1) > *data_end)
        return -1;
    return 0;
}

static __always_inline __u16 bpf_ntohs(__u16 val) {
    return (val << 8) | (val >> 8);
}

SEC("xdp")
int xdp_ddos_defense(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth;

    if (parse_eth(&data, &data_end, &eth) < 0)
        return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;
    
    struct iphdr *ip;
    data += sizeof(struct ethhdr);
    if (parse_ip(&data, &data_end, &ip) < 0)
        return XDP_PASS;

    struct flow_key key = {};
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.proto  = ip->protocol;

    // TCP 프로토콜 처리 (SYN Flood 방어)
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = data + sizeof(struct iphdr);
        if ((void*)(tcp + 1) > data_end)
            return XDP_PASS;
       // key.src_port = tcp->source;
      //  key.dst_port = tcp->dest;
     

        if (tcp->syn && !tcp->ack) {
            __u32 *count, init_val = 1;
            count = bpf_map_lookup_elem(&flow_count, &key);
            if (count) {
                // 임계치 이상이면 카운트를 증가시키지 않고 바로 드랍
                if (*count >= TCP_SYN_THRESHOLD) {
                    bpf_printk("xdp_ddos_defense: Dropping TCP packet: src_ip=0x%x, dst_ip=0x%x, proto=%d, count=%d\n",
                               key.src_ip, key.dst_ip, key.proto, *count);
                    return XDP_DROP;
                }
                __u32 new_count = *count + 1;
                bpf_map_update_elem(&flow_count, &key, &new_count, BPF_EXIST);
                bpf_printk("xdp_ddos_defense: TCP flow update: src_ip=0x%x, dst_ip=0x%x, proto=%d, count=%d\n",
                           key.src_ip, key.dst_ip,  key.proto, new_count);
            } else {
                bpf_map_update_elem(&flow_count, &key, &init_val, BPF_ANY);
                bpf_printk("xdp_ddos_defense: New TCP flow: src_ip=0x%x, dst_ip=0x%x, proto=%d, count=1\n",
                           key.src_ip, key.dst_ip,  key.proto);
            }
        }
    }
    // UDP 프로토콜 처리 (UDP Flood 방어)
    else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = data + sizeof(struct iphdr);
        if ((void*)(udp + 1) > data_end)
            return XDP_PASS;
        // key.src_port = udp->source;
        // key.dst_port = udp->dest;

        __u32 *count, init_val = 1;
        count = bpf_map_lookup_elem(&flow_count, &key);
        if (count) {
            if (*count >= UDP_THRESHOLD) {
                bpf_printk("xdp_ddos_defense: Dropping UDP packet: src_ip=0x%x, dst_ip=0x%x,  proto=%d, count=%d\n",
                           key.src_ip, key.dst_ip,  key.proto, *count);
                return XDP_DROP;
            }
            __u32 new_count = *count + 1;
            bpf_map_update_elem(&flow_count, &key, &new_count, BPF_EXIST);
            bpf_printk("xdp_ddos_defense: UDP flow update: src_ip=0x%x, dst_ip=0x%x,  proto=%d, count=%d\n",
                       key.src_ip, key.dst_ip,  key.proto, new_count);
        } else {
            bpf_map_update_elem(&flow_count, &key, &init_val, BPF_ANY);
            bpf_printk("xdp_ddos_defense: New UDP flow: src_ip=0x%x, dst_ip=0x%x, proto=%d, count=1\n",
                       key.src_ip, key.dst_ip,  key.proto);
        }
    }
    return XDP_PASS;
}


// SEC("lsm/sb_mount")
// int BPF_PROG(sb_mount, const char *dev_name, const struct path *path,
// 	const char *type, unsigned long flags, void *data)
// {
// 	//bpf_printk("lsm_hook: fs: sb_mount\n");

// 	event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e) {
//         return 0;
//     }    
    
//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         return 0;
//     }

//     get_process_path(e->data.source, sizeof(e->data.source));
    
//     e->event_id = SECID_SB_MOUNT;
//     e->retval = 0; 
    
//     bpf_ringbuf_submit(e, 0);

// 	return 0;
// }

// SEC("lsm/sb_remount")
// int BPF_PROG(sb_remount, struct super_block *sb, void *mnt_opts)
// {
// 	//bpf_printk("lsm_hook: fs: sb_remount\n");

// 	event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e) {
//         return 0;
//     }    
    
//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         return 0;
//     }

//     get_process_path(e->data.source, sizeof(e->data.source));
    
//     e->event_id = SECID_SB_REMOUNT;
//     e->retval = 0; 
    
//     bpf_ringbuf_submit(e, 0);

// 	return 0;
// }

// SEC("lsm/sb_umount")
// int BPF_PROG(sb_umount, struct vfsmount *mnt, int flags)
// {
// 	//bpf_printk("lsm_hook: fs: sb_umount\n");

// 	event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e) {
//         return 0;
//     }    
    
//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         return 0;
//     }

//     get_process_path(e->data.source, sizeof(e->data.source));
    
//     e->event_id = SECID_SB_UMOUNT;
//     e->retval = 0; 
    
//     bpf_ringbuf_submit(e, 0);

// 	return 0;
// }

// SEC("lsm/socket_bind")
// int BPF_PROG(socket_bind, struct socket *sock, struct sockaddr *address,
// 	 int addrlen)
// {
// 	//bpf_printk("lsm_hook: socket: socket_bind\n");
	
// 	event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e) {
//         return 0;
//     }    
    
//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         return 0;
//     }
    
//     get_process_path(e->data.source, sizeof(e->data.source));

//     e->event_id = SECID_SOCKET_BIND;
//     e->retval = 0; 
    
//     bpf_ringbuf_submit(e, 0);

// 	return 0;
// }

// SEC("lsm/socket_connect")
// int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address,
// 	 int addrlen)
// {
// 	//bpf_printk("lsm_hook: socket: socket_connect\n");

//     __u32 pid_ns_id;
//     struct task_struct *task = (struct task_struct *)bpf_get_current_task();
//     pid_ns_id = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
//     bpf_printk("socket_connect_bpf: pid_ns_id=%u\n", pid_ns_id);

// 	event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e) {
//         bpf_printk("pid_ns_id=%u ringbuf_reserve error", pid_ns_id);
//         return 0;
//     }    
    
//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         bpf_printk("pid_ns_id=%u ringbuf_discard error", pid_ns_id);
//         return 0;
//     }
    
//     get_process_path(e->data.source, sizeof(e->data.source));
    
//     e->event_id = SECID_SOCKET_CONNECT;
//     e->retval = 0; 
    
//     bpf_ringbuf_submit(e, 0);

//     bpf_printk("pid_ns_id=%u policy check start", pid_ns_id);

//     struct network_policy net = {};
//     // Handle IPv4
//     if (address->sa_family == AF_INET) {
//         struct sockaddr_in *addr_in = (struct sockaddr_in *)address;
//         net.ip = addr_in->sin_addr.s_addr;  // Extract IPv4 address (in network byte order)
//         net.port = addr_in->sin_port;        // Port is in network byte order
//         net.protocol = IPPROTO_TCP;          // Defaulting to TCP; change as necessary for your use case
//     } 
//     // Handle IPv6
//     else if (address->sa_family == AF_INET6) {
//         struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)address;
//         // Set IP to 0 or handle accordingly for IPv6
//         net.ip = 0;  // This could be adjusted depending on your policy handling needs
//         net.port = addr_in6->sin6_port;  // Port is in network byte order
//         net.protocol = IPPROTO_IPV6;      // Defaulting to IPv6; change as necessary for your use case
//     }

//     // Determine the protocol based on the type of socket if needed
//     // For example, you might want to set it based on the socket type:
//     // - SOCK_STREAM (TCP)
//     // - SOCK_DGRAM (UDP)
//     switch (sock->type) {
//         case SOCK_STREAM:
//             net.protocol = IPPROTO_TCP;  // For TCP
//             break;
//         case SOCK_DGRAM:
//             net.protocol = IPPROTO_UDP;   // For UDP
//             break;
//         // Add other types as necessary, like SOCK_RAW for ICMP
//         default:
//             net.protocol = IPPROTO_IP;     // Default to IP
//             break;
//     }

//     net.flags = POLICY_NET_CONNECT;

//     int eperm = match_policy(POLICY_NETWORK, &net);

//     bpf_printk("pid_ns_id=%u, ip=%u, port=%u, protocol=%u, eperm=%d", pid_ns_id, net.ip, net.port, net.protocol, eperm);

//     if (eperm != 0) {
//         bpf_printk("Permission denied\n");
//         return -1;
//     }

// 	return 0;
// }

// SEC("lsm/kernel_module_request")
// int BPF_PROG(kernel_module_request, char *kmod_name)
// {
//     //bpf_printk("lsm_hook: kernel: kernel_module_request\n");
//     event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e) {
//         return 0;
//     }    
    
//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         return 0;
//     }

//     get_process_path(e->data.source, sizeof(e->data.source));
    
//     e->event_id = SECID_KERNEL_MODULE_REQUEST;
//     e->retval = 0; 
    
//     bpf_ringbuf_submit(e, 0);

// 	return 0;
// }

// SEC("lsm/kernel_read_file")
// int BPF_PROG(kernel_read_file, struct file *file, enum kernel_read_file_id id)
// {
//     //bpf_printk("lsm_hook: kernel: kernel_read_file\n");
//     event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e) {
//         return 0;
//     }    
    
//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         return 0;
//     }

//     get_process_path(e->data.source, sizeof(e->data.source));
    
//     e->event_id = SECID_KERNEL_READ_FILE;
//     e->retval = 0; 
    
//     bpf_ringbuf_submit(e, 0);

//     return 0;

// }

// SEC("lsm/bprm_creds_from_file")
// int BPF_PROG(bprm_creds_from_file, struct linux_binprm *bprm, struct file *file)
// {
//     //bpf_printk("lsm_hook: exec: bprm_creds_from_file\n");
//     event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e) {
//         return 0;
//     }    
    
//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         return 0;
//     }

//     get_process_path(e->data.source, sizeof(e->data.source));
    
//     e->event_id = SECID_BPRM_CREDS_FROM_FILE;
//     e->retval = 0; 
    
//     bpf_ringbuf_submit(e, 0);

//     return 0;

// }

// SEC("lsm/socket_create")
// int BPF_PROG(socket_create, struct socket *sock, int family, int type, int protocol, int kern)
// {
//     //bpf_printk("lsm_hook: socket: socket_create\n");
//     event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e) {
//         return 0;
//     }    
    
//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         return 0;
//     }

//     get_process_path(e->data.source, sizeof(e->data.source));
    
//     e->event_id = SECID_SOCKET_CREATE;
//     e->retval = 0; 
    
//     bpf_ringbuf_submit(e, 0);

//     return 0;

// }

// SEC("lsm/socket_accept")
// int BPF_PROG(socket_accept, struct socket *sock, struct socket *newsock)
// {
//     //bpf_printk("lsm_hook: socket: socket_accept\n");
//     event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e) {
//         return 0;
//     }    
    
//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         return 0;
//     }

//     get_process_path(e->data.source, sizeof(e->data.source));
    
//     e->event_id = SECID_SOCKET_ACCEPT;
//     e->retval = 0; 
    
//     bpf_ringbuf_submit(e, 0);

//     return 0;

// }


// SEC("lsm/capable")
// int BPF_PROG(capable, struct task_struct *task, const struct cred *cred, int cap)
// {
//     //bpf_printk("lsm_hook: task: capable\n");
//     event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e) {
//         return 0;
//     }    
    
//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         return 0;
//     }

//     get_process_path(e->data.source, sizeof(e->data.source));

//     e->event_id = SECID_CAPABLE;
//     e->retval = 0; 
    
//     bpf_ringbuf_submit(e, 0);

//     return 0;

// }

// SEC("lsm/path_mknod")
// int BPF_PROG(path_mknod, struct path *path, umode_t mode, dev_t dev)
// {
//     //bpf_printk("lsm_hook: fs: path_mknod\n");
//     event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e) {
//         return 0;
//     }    
    
//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         return 0;
//     }
    
//     get_process_path(e->data.source, sizeof(e->data.source));

//     e->event_id = SECID_PATH_MKNOD;
//     e->retval = 0; 
    
//     bpf_ringbuf_submit(e, 0);

//     return 0;

// }



// SEC("lsm/path_symlink")
// int BPF_PROG(path_symlink, struct path *path, struct path *target)
// {
//     //bpf_printk("lsm_hook: fs: path_symlink\n");
//     event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e) {
//         return 0;
//     }    
    
//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         return 0;
//     }

//     get_process_path(e->data.source, sizeof(e->data.source));

//     e->event_id = SECID_PATH_SYMLINK;
//     e->retval = 0; 
    
//     bpf_ringbuf_submit(e, 0);

//     return 0;

// }



// SEC("lsm/path_link")
// int BPF_PROG(path_link, struct dentry *old_dentry, struct path *new_dir, struct dentry *new_dentry)
// {
//     //bpf_printk("lsm_hook: fs: path_link\n");
//     event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e) {
//         return 0;
//     }    
    
//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         return 0;
//     }

//     get_process_path(e->data.source, sizeof(e->data.source));

//     e->event_id = SECID_PATH_LINK;
//     e->retval = 0; 
    
//     bpf_ringbuf_submit(e, 0);

//     return 0;

// }

// SEC("lsm/path_rename")
// int BPF_PROG(path_rename, struct path *old_path, struct path *new_path)
// {
//     //bpf_printk("lsm_hook: fs: path_rename\n");
//     event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e) {
//         return 0;
//     }    
    
//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         return 0;
//     }

//     get_process_path(e->data.source, sizeof(e->data.source));
    
//     e->event_id = SECID_PATH_RENAME;
//     e->retval = 0; 
    
//     bpf_ringbuf_submit(e, 0);

//     return 0;

// }


// SEC("lsm/path_truncate")
// int BPF_PROG(path_truncate, struct path *path, loff_t length)
// {
//     //bpf_printk("lsm_hook: fs: path_truncate\n");
//     event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e) {
//         return 0;
//     }    
    
//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         return 0;
//     }

//     get_process_path(e->data.source, sizeof(e->data.source));
    
//     e->event_id = SECID_PATH_TRUNCATE;
//     e->retval = 0; 
    
//     bpf_ringbuf_submit(e, 0);

//     return 0;

// }

// SEC("lsm/mmap_file")
// int BPF_PROG(mmap_file, struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags)
// {
//     //bpf_printk("lsm_hook: file: mmap_file\n");
//     event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e) {
//         return 0;
//     }    
    
//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         return 0;
//     }

//     get_process_path(e->data.source, sizeof(e->data.source));
    
//     e->event_id = SECID_MMAP_FILE;
//     e->retval = 0; 
    
//     bpf_ringbuf_submit(e, 0);

//     return 0;

// }


// SEC("lsm/task_fix_setuid")
// int BPF_PROG(task_fix_setuid, struct cred *new, const struct cred *old, int flags)
// {
//     struct task_struct *task = (struct task_struct *)bpf_get_current_task();
//     if (!should_monitor(task))
//         return 0;

//     event *e = reserve_and_init_event();
//     if (!e)
//         return 0;

//     int ret = init_context(e);
//     if (ret < 0) {
//         bpf_ringbuf_discard(e, 0);
//         return 0;
//     }

//     get_process_path(e->data.source, sizeof(e->data.source));
//     e->event_id = SECID_TASK_FIX_SETUID;

//     __u32 policy_flags = match_policy(task, POLICY_FILE, e->comm);
//     bpf_printk("setuid path %d \n", e->comm);
//     if (policy_flags & POLICY_FILE_SET_UID)
//         ret = -1;
//     else
//         ret = 0;

//     e->retval = ret;
//     process_event_handler(e, policy_flags);
//     return ret;
// }