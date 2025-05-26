// File: src/loader.cpp

#include <arpa/inet.h>    // ntohl(), inet_ntop()
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/if_ether.h>   // ETH_P_ALL
#include <linux/if_link.h>    // XDP_FLAGS_*
#include <linux/if_packet.h>  // AF_PACKET, ETH_P_ALL
#include <net/if.h>           // if_nametoindex()
#include <signal.h>           // signal()
#include <sys/resource.h>     // setrlimit()
#include <sys/socket.h>       // socket(), setsockopt()
#include <unistd.h>           // close()

#include <iostream>
#include <string>

#include "crosslayer.h"

// -----------------------------------------------------------------------------
// 전역 변수들
// -----------------------------------------------------------------------------
static struct bpf_object *obj_xdp   = nullptr;
static struct bpf_object *obj_tc    = nullptr;
static struct bpf_object *obj_sock  = nullptr;
static struct bpf_object *obj_ctrl  = nullptr;

static int xdp_prog_fd  = -1;
static int sock_prog_fd = -1;
static int raw_fd       = -1;
static int ifindex      = 0;

static struct bpf_tc_hook tc_hook         = {};
static bool             tc_hook_active   = false;

static struct bpf_link *ctrl_links[8];
static int              num_ctrl_links   = 0;

// -----------------------------------------------------------------------------
// clg_load_probes: BPF 오브젝트 로드 및 프로브 부착
// -----------------------------------------------------------------------------
clg_error_t clg_load_probes(const char *bpf_dir,
                            const char *ifname,
                            clg_handle_t **out) {
    // 0) RLIMIT_MEMLOCK 무제한으로 설정
    struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rl)) {
        perror("setrlimit");
        return CLG_ERR_INVALID_ARG;
    }

    // 사용자 핸들 할당
    clg_handle_t *h = new clg_handle_t{};
    *out = h;

    // 1) control-plane 프로브 로드
    {
        std::string path = std::string(bpf_dir) + "/ctrl_probe.o";
        obj_ctrl = bpf_object__open_file(path.c_str(), nullptr);
        if (!obj_ctrl || libbpf_get_error(obj_ctrl)) {
            std::cerr << "ERROR: open " << path << "\n";
            return CLG_ERR_LOAD;
        }
        if (int err = bpf_object__load(obj_ctrl)) {
            std::cerr << "ERROR: load " << path << " (" << err << ")\n";
            return CLG_ERR_LOAD;
        }
        h->objs[3] = obj_ctrl;
        std::cout << "Loaded BPF object: " << path << "\n";
    }

    // 2) control-plane 프로그램 attach
    {
        struct bpf_program *prog;
        bpf_object__for_each_program(prog, obj_ctrl) {
            struct bpf_link *link = bpf_program__attach(prog);
            if (libbpf_get_error(link)) {
                std::cerr << "WARN: attach ctrl prog "
                          << bpf_program__name(prog) << "\n";
            } else if (num_ctrl_links < 8) {
                ctrl_links[num_ctrl_links++] = link;
                std::cout << "Attached control-plane: "
                          << bpf_program__name(prog) << "\n";
            }
        }
    }

    // 3) XDP/TC/SOCK 프로브 로드
    auto load_obj = [&](int idx, const char *name) {
        std::string path = std::string(bpf_dir) + "/" + name;
        struct bpf_object *obj = bpf_object__open_file(path.c_str(), nullptr);
        if (!obj || libbpf_get_error(obj)) {
            std::cerr << "ERROR: open " << path << "\n";
            exit(1);
        }
        if (int err = bpf_object__load(obj)) {
            std::cerr << "ERROR: load " << path << " (" << err << ")\n";
            exit(1);
        }
        h->objs[idx] = obj;
        std::cout << "Loaded BPF object: " << path << "\n";
        return obj;
    };
    obj_xdp  = load_obj(0, "xdp_record.o");
    obj_tc   = load_obj(1, "tc_record.o");
    obj_sock = load_obj(2, "sock_record.o");

    // 4) 인터페이스 인덱스 조회
    if ((ifindex = if_nametoindex(ifname)) == 0) {
        std::cerr << "ERROR: invalid interface: " << ifname << "\n";
        return CLG_ERR_INVALID_ARG;
    }
    std::cout << "Using interface '" << ifname
              << "' (ifindex=" << ifindex << ")\n";

    // 5) XDP attach
    {
        struct bpf_program *xdp_prog =
            bpf_object__find_program_by_name(obj_xdp, "xdp_record");
        xdp_prog_fd = bpf_program__fd(xdp_prog);
        if (bpf_set_link_xdp_fd(ifindex,
                                xdp_prog_fd,
                                XDP_FLAGS_SKB_MODE)) {
            perror("bpf_set_link_xdp_fd");
            return CLG_ERR_ATTACH;
        }
        std::cout << "XDP attached on ifindex " << ifindex << "\n";
    }

    // 6) TC Ingress attach
    {
        tc_hook.sz           = sizeof(tc_hook);
        tc_hook.ifindex      = ifindex;
        tc_hook.attach_point = BPF_TC_INGRESS;
        if (bpf_tc_hook_create(&tc_hook) && errno != EEXIST) {
            perror("bpf_tc_hook_create");
            return CLG_ERR_ATTACH;
        }
        tc_hook_active = true;

        auto *tc_prog = bpf_object__find_program_by_name(obj_tc, "tc_record");
        DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts,
                            .prog_fd = bpf_program__fd(tc_prog),
                            .flags  = BPF_TC_F_REPLACE);
        if (bpf_tc_attach(&tc_hook, &tc_opts)) {
            perror("bpf_tc_attach");
            return CLG_ERR_ATTACH;
        }
        std::cout << "TC ingress attached\n";
    }

    // 7) SOCK_RAW filter attach
    {
        raw_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (raw_fd < 0) {
            perror("socket(AF_PACKET)");
            return CLG_ERR_ATTACH;
        }
        struct bpf_program *sock_prog =
            bpf_object__find_program_by_name(obj_sock, "sock_record");
        sock_prog_fd = bpf_program__fd(sock_prog);
        if (setsockopt(raw_fd, SOL_SOCKET, SO_ATTACH_BPF,
                       &sock_prog_fd,
                       sizeof(sock_prog_fd))) {
            perror("SO_ATTACH_BPF");
            return CLG_ERR_ATTACH;
        }
        std::cout << "Socket filter attached (fd=" << raw_fd << ")\n";
    }

    return CLG_OK;
}

// -----------------------------------------------------------------------------
// clg_unload_probes: 해제 및 정리
// -----------------------------------------------------------------------------
clg_error_t clg_unload_probes(clg_handle_t *h) {
    if (!h) return CLG_ERR_INVALID_ARG;

    // 1) XDP detach
    if (ifindex) {
        bpf_set_link_xdp_fd(ifindex, -1, 0);
    }
    // 2) TC ingress detach
    if (tc_hook_active) {
        bpf_tc_detach(&tc_hook, nullptr);
        bpf_tc_hook_destroy(&tc_hook);
    }
    // 3) SOCK detach
    if (raw_fd >= 0) {
        setsockopt(raw_fd, SOL_SOCKET, SO_DETACH_BPF,
                   &sock_prog_fd,
                   sizeof(sock_prog_fd));
        close(raw_fd);
    }
    // 4) control-plane links destroy
    for (int i = 0; i < num_ctrl_links; i++) {
        bpf_link__destroy(ctrl_links[i]);
    }
    // 5) close all objects
    for (auto &obj : h->objs) {
        if (obj) bpf_object__close(obj);
    }

    delete h;
    std::cout << "Unloaded all BPF objects\n";
    return CLG_OK;
}
