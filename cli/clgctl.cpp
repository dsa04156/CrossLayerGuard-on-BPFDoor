// cli/clgctl.cpp

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <signal.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "crosslayer.h"  // clg_load_probes, clg_start_aggregator, clg_unload_probes, clg_error_t

static int whitelist_map_fd = -1;

// ── BPF 오브젝트에서 map_name 맵 fd 얻기 ───────────────────────────────
static int get_map_fd(const char* obj_path, const char* map_name) {
    struct bpf_object* obj = bpf_object__open_file(obj_path, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening %s: %s\n", obj_path,
                strerror(-libbpf_get_error(obj)));
        return -1;
    }
    if (int err = bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading %s: %s\n", obj_path, strerror(-err));
        bpf_object__close(obj);
        return -1;
    }
    struct bpf_map* map = bpf_object__find_map_by_name(obj, map_name);
    if (!map) {
        fprintf(stderr, "ERROR: map '%s' not found in %s\n", map_name, obj_path);
        bpf_object__close(obj);
        return -1;
    }
    int fd = bpf_map__fd(map);
    if (fd < 0) {
        fprintf(stderr, "ERROR: bpf_map__fd failed for %s in %s\n",
                map_name, obj_path);
        bpf_object__close(obj);
        return -1;
    }
    // obj는 계속 살아 있어야 map fd가 유효합니다.
    return fd;
}

// ── whitelist_ips 맵 fd 얻기 ─────────────────────────────────────────
static int open_whitelist_map() {
    const char* pin_path = "/sys/fs/bpf/whitelist_ips";
    whitelist_map_fd = bpf_obj_get(pin_path);
    if (whitelist_map_fd < 0) {
        fprintf(stderr, "ERROR: opening pinned map %s: %s\n", pin_path,
                strerror(errno));
        return -1;
    }
    return 0;
}

// ── 화이트리스트에 IP 추가 ─────────────────────────────────────────────
static int cmd_whitelist_add(const char* ip_str) {
    if (open_whitelist_map()) return 1;
    in_addr_t ip_nbo;
    if (inet_pton(AF_INET, ip_str, &ip_nbo) != 1) {
        fprintf(stderr, "Invalid IPv4: %s\n", ip_str);
        return 1;
    }
    uint32_t key = ip_nbo;
    uint8_t val = 1;
    if (bpf_map_update_elem(whitelist_map_fd, &key, &val, BPF_ANY) != 0) {
        perror("bpf_map_update_elem");
        return 1;
    }
    printf("Whitelist ADD: %s\n", ip_str);
    return 0;
}

// ── 화이트리스트 전체 조회 ───────────────────────────────────────────────
static int cmd_whitelist_list() {
    if (open_whitelist_map()) return 1;

    uint32_t key, next_key;
    uint8_t val;
    bool empty = true;

    printf("Current whitelist:\n");
    if (bpf_map_get_next_key(whitelist_map_fd, NULL, &key) == 0) {
        do {
            bpf_map_lookup_elem(whitelist_map_fd, &key, &val);
            struct in_addr a = { .s_addr = key };
            printf("  - %s\n", inet_ntoa(a));
            empty = false;
        } while (bpf_map_get_next_key(whitelist_map_fd, &key, &next_key) == 0
                 && (key = next_key, true));
    }

    if (empty) {
        printf("  (none)\n");
    }
    return 0;
}

// ── 화이트리스트에서 IP 제거 ───────────────────────────────────────────
static int cmd_whitelist_del(const char* ip_str) {
    if (open_whitelist_map()) return 1;
    in_addr_t ip_nbo;
    if (inet_pton(AF_INET, ip_str, &ip_nbo) != 1) {
        fprintf(stderr, "Invalid IPv4: %s\n", ip_str);
        return 1;
    }
    uint32_t key = ip_nbo;
    if (bpf_map_delete_elem(whitelist_map_fd, &key) != 0) {
        perror("bpf_map_delete_elem");
        return 1;
    }
    printf("Whitelist DEL: %s\n", ip_str);
    return 0;
}

// ── 시그널 핸들러 ─────────────────────────────────────────────────────
static volatile bool stop_requested = false;
static void sig_int(int signo) {
    stop_requested = true;
}

int main(int argc, char** argv) {
    // 1. 화이트리스트 관리 모드
    if (argc >= 2 && strcmp(argv[1], "whitelist") == 0) {
        if (argc == 3 && strcmp(argv[2], "list") == 0)
            return cmd_whitelist_list();
        if (argc == 4) {
            const char* action = argv[2];
            const char* ip_str = argv[3];
            if (strcmp(action, "add") == 0) return cmd_whitelist_add(ip_str);
            if (strcmp(action, "del") == 0) return cmd_whitelist_del(ip_str);
        }
        fprintf(stderr,
                "Usage:\n"
                "  %s whitelist list\n"
                "  %s whitelist add <IP>\n"
                "  %s whitelist del <IP>\n",
                argv[0], argv[0], argv[0]);
        return 1;
    }

    // 2. 모니터링 실행 모드
    if (argc == 3) {
        const char* bpf_dir = argv[1];
        const char* ifname  = argv[2];

        // 시그널 핸들러 등록
        signal(SIGINT, sig_int);
        signal(SIGTERM, sig_int);

        // 2.1 BPF 프로브 로드 및 attach
        clg_handle_t* handle = nullptr;
        if (clg_load_probes(bpf_dir, ifname, &handle) != CLG_OK) {
            fprintf(stderr, "ERROR: clg_load_probes() failed\n");
            return 1;
        }

        // 2.2 perf-map FD를 handle에 저장
        handle->fd_xdp  = bpf_map__fd(
            bpf_object__find_map_by_name(handle->objs[0], "events"));
        handle->fd_tc   = bpf_map__fd(
            bpf_object__find_map_by_name(handle->objs[1], "events"));
        handle->fd_sock = bpf_map__fd(
            bpf_object__find_map_by_name(handle->objs[2], "events"));
        handle->fd_ctrl = bpf_map__fd(
            bpf_object__find_map_by_name(handle->objs[3], "ctrl_events"));

        // 2.3 Aggregator 시작 (블록, Ctrl-C로 종료)
        printf("Starting event loop (Ctrl+C to stop)...\n");
        clg_error_t ret = clg_start_aggregator(handle);

        // 2.4 언로드 & 정리
        printf("Stopping probes...\n");
        clg_unload_probes(handle);

        return ret == CLG_OK ? 0 : 1;
    }

    // 잘못된 사용법
    fprintf(stderr,
            "Usage:\n"
            "  %s whitelist list\n"
            "  %s whitelist add <IP>\n"
            "  %s whitelist del <IP>\n"
            "  %s <bpf_obj_dir> <interface>\n",
            argv[0], argv[0], argv[0], argv[0]);
    return 1;
}
