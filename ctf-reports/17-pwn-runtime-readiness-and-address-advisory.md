# 17. Pwn runtime readiness와 address-resolution advisory

**기록일:** 2026-07-30

**코드 기준:** `d3cb714` (`fix: observe pwn faults without host core dumps`)

**판정:** Pwn D→V gate가 현재 고정 Docker 이미지에서 실제로 실행되며,
strategy-scoped address-resolution advisory의 치환 방지 계약이 추가됨.
runtime snapshot, leak provenance, primitive/exploit gate와 solve 성능 향상은
아직 미구현 또는 미측정

## 결론

[16번 기록](16-pwn-crash-gate-and-failure-replay.md)의 상태·실행·failure
capsule 구조는 있었지만 실제 pinned image에는 `pwn_crash_v1` capability가
없었다. 또한 host가 piped `core_pattern`을 사용해 이전 producer는 실행
전에 항상 거부됐다. 따라서 당시 신뢰할 수 있던 것은 source-level 계약과
mocked engine 회귀였고, 실제 대회 runtime readiness는 아니었다.

이번 변경은 두 병목을 닫았다.

1. `doctor`가 stale tag/digest 또는 필수 capability/attestation 누락을
   `ok=false`로 판정한다.
2. crash producer가 core 파일이나 host core handler에 의존하지 않고,
   지원하는 fault를 ptrace stop에서 관측·억제한다.

새 exact image에서 Pwn 3+3 실행과 보안 반례 probe, 기존 Rev 3+3, pin과
doctor를 모두 통과했다. 이것은 D→V 실행 가능성의 증거이지 working exploit,
flag 또는 solve-rate 개선의 증거는 아니다.

## 구현 중 발견한 반례

첫 ptrace 초안도 그대로 채택하지 않았다. 독립 감사에서 다음 false proof와
containment 우회가 실제 재현됐다.

- fork child의 `SIGSEGV`를 `SIGKILL`로 바꾼 뒤 parent를 계속 실행하면
  `waitpid()` 의미가 달라져 producer가 없던 root crash를 만들 수 있었다.
- `CLONE_UNTRACED | SIGCHLD` child가 setsid 후 살아남아 tracee set과
  process-group reap을 모두 우회했다.
- 다른 thread가 signal disposition을 바꾸면 caught/default 판정과 signal
  delivery 사이에 TOCTOU가 생겼다.
- 관측하지 않은 terminal core signal도 일반 signaled 결과로 내보내면
  evaluator의 allowed-signal 경로에 들어갈 수 있었다.

현재 v1은 성공 범위를 넓히지 않고 fail-closed한다.

| 상황 | v1 판정 |
| --- | --- |
| single-thread root의 observed default fault stop | 원 signal을 기록하고 전달 전 억제 |
| caught/ignored core signal | producer `ERROR` |
| non-root child core signal | producer `ERROR` |
| thread가 관측된 root의 core signal | producer `ERROR` |
| delivery stop 없이 terminal core signal | producer `ERROR` |
| numeric exit 139 | 정상적인 numeric exit |

exec 전 fixed classic-BPF seccomp filter는 `CLONE_UNTRACED`와 cross-Tgid
`CLONE_SIGHAND`를 `EPERM`, `clone3`, x32 high syscall bit와 architecture
mismatch를 `ENOSYS`로 보낸다. seccomp의 signal-producing kill action은
사용하지 않는다. 일반 pthread clone은 허용하지만, thread가 한 번이라도
관측된 실행의 core stop은 성공 증거로 쓰지 않는다.

## 실제 Docker 검증

release image:
`sha256:9b685a50c54f6b67013ea72150ebcea47d837faa0e505de8332e4b08a12bfb4f`

`scripts/check-pwn-docker-crash.py`는 tracked C fixture를 host에서 컴파일한
뒤 target 실행은 모두 challenge-scoped clean Docker sandbox에서 수행한다.

- direct `SIGSEGV` payload 3회: signal 11, 3/3
- 빈 input control 3회: 정상 exit, 3/3
- semantic verdict: `CONFIRMED`
- `CLONE_UNTRACED` probe: filter 차단 후 target exit 0
- 정상 pthread probe: target exit 0
- caught fault: `caught_or_ignored_core_signal_unsupported`
- worker-thread fault: `multithreaded_core_signal_unsupported`
- fork-child fault: `non_root_core_signal_unsupported`
- 총 11개 clean workspace, network none, complete/non-truncated transport,
  live workspace residue 없음

같은 exact image에서 Managed Rev 원본 바이너리 oracle의 positive 3회와
negative 3회도 통과했다. pin 후 `doctor`는 필수 capability 9/9,
attestation error 0, warning 0이었다.

같은 code tree를 Python 3.13.14로 검증한 host 전체 회귀는 1,025개
테스트가 210.837초에 통과했다(측정 wall 200.42초, exit 0). 실제 Docker
smoke와 host 회귀는 서로 다른 증거이며 어느 쪽도 solve 성능으로 집계하지
않는다.

## Address-resolution advisory

`ctfos.pwn.leak_requirement` v1은 leak stage를 통과시키는 계약이 아니다.
한 exploit strategy가 선언한 한 dependency에 대해 runtime address
resolution 필요성을 분류하는 pure advisory다.

결과는 strategy hash와 dependency ID뿐 아니라 source manifest/hash/size,
ELF profile evidence hash에 결속된다. validator는 결과 안의 값을 신뢰하지
않고 engine이 준 expected dependency/profile/source 값으로 expected result를
재생성한다. 다른 relative dependency나 ET_EXEC profile로 coherent하게
바꾼 결과도 거부된다.

모든 result는 다음 권한을 명시적으로 갖지 않는다.

- global leak N/A
- global runtime address-resolution N/A
- leak 존재 또는 leak 필수 증명
- primitive 또는 proof
- 다음 stage 진입

따라서 모델이 dependency를 누락하거나 전부 relative로 선언해도 L단계를
건너뛸 수 없다. runtime disclosure provenance와 downstream
randomized-layout exploit replay가 별도 실행 계약으로 붙기 전에는 이
advisory를 gate pass로 집계하지 않는다.

## 성능 주장 경계

이번 검증에는 model API call이나 원격 CTF request가 없다. 따라서 다음은
아직 주장할 수 없다.

- solve@1 또는 pass^2/3 개선
- median time-to-first-valid-result 단축
- 사람 개입 감소
- thin baseline 대비 향상
- hidden/live 또는 ExploitGym 성능 향상

다음 구현은 confirmed crash의 별도 clean replay에서 fixed ptrace producer가
register와 `/proc/<tgid>/maps`를 bounded artifact로 수집하는 runtime
snapshot이다. 모델이 GDB command, breakpoint, PID, register 목록이나 target
argv를 제공하는 인터페이스는 만들지 않는다. snapshot 실패는 이미 확인된
crash verdict를 되돌리지 않고 독립 child diagnostic gate로 남긴다.
