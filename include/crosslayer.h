#ifndef CROSSLAYER_H
#define CROSSLAYER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

// 라이브러리 에러 코드
typedef enum {
    CLG_OK              =  0,
    CLG_ERR_LOAD        = -1,
    CLG_ERR_ATTACH      = -2,
    CLG_ERR_AGGREGATOR  = -3,
    CLG_ERR_INVALID_ARG = -4
} clg_error_t;

// 전방 선언: 내부 구현에서만 정의
struct bpf_object;

// 네 개의 BPF 오브젝트 핸들과 perf-map FD를 담은 구조체
typedef struct clg_handle {
    struct bpf_object *objs[4];  // xdp, tc, sock, ctrl 객체 핸들
    int fd_xdp;                  // XDP perf map FD
    int fd_tc;                   // TC perf map FD
    int fd_sock;                 // SOCK perf map FD
    int fd_ctrl;                 // CTRL perf map FD
} clg_handle_t;

/**
 * clg_load_probes
 *  - bpf_dir: eBPF .o 파일들이 위치한 디렉토리 경로
 *  - ifname:  프로브를 attach 할 네트워크 인터페이스 이름
 *  - out:      성공 시 할당된 handle 포인터 반환
 *
 * 반환: CLG_OK (0)이면 성공, 음수 값(clg_error_t)이면 실패
 */
clg_error_t clg_load_probes(const char *bpf_dir,
                            const char *ifname,
                            clg_handle_t **out);

/**
 * clg_start_aggregator
 *  - h: clg_load_probes로 생성된 handle
 *    내부에 저장된 perf-map FD를 이용해 이벤트 루프를 시작
 *    SIGINT/SIGTERM 수신 시 종료
 *
 * 반환: CLG_OK (0)이면 정상 종료, 음수 값(clg_error_t)이면 오류
 */
clg_error_t clg_start_aggregator(clg_handle_t *h);

/**
 * clg_unload_probes
 *  - h: 프로브 로드 및 attach 해제, map unpin 등
 *
 * 반환: CLG_OK 또는 오류 코드
 */
clg_error_t clg_unload_probes(clg_handle_t *h);

#ifdef __cplusplus
}
#endif

#endif  // CROSSLAYER_H
