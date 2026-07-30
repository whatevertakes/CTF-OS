# 18. Zone one-cycle live diagnostic

**기록일:** 2026-07-30

**대상:** `NYU_PWN_V20250206_PASS2/pwn/nyu-pwn-01`

**실행 코드 기준:** `24d2c4a`

**판정:** 기존 terminal contract failure는 재발하지 않았고 all-Sol
Captain + 3-worker wave와 tool dispatch까지 완료됐다. 그러나 stale adapter
seed와 managed command의 shell/argv 의미 불일치 때문에 target 관측 증거는
생성되지 않았다. solve 또는 partial Pwn gate 개선으로 집계하지 않는다.

## 실행 경계

- 사람이 이미 선택한 `zone` 한 challenge만 열었다.
- service는 host port, bind mount, device, privileged/capability 추가 없이
  internal `ctfnet`에만 기동했다.
- pinned `ctf-os:core`
  `sha256:b35630c32f0ff00af423e81264a4ef57a56244fc5d0282d99aa505b4b9a6a5aa`
  에서 최초 TCP readiness를 확인했다.
- target generation 2만 proxy allowlist로 선택했다.
- 외부 검색, write-up, solver, hidden flag, 자동 제출을 사용하지 않았다.
- 종료 후 session cancel, target revoke, service stop, network 제거를
  완료했다. 최종 상태는 rev 49 `NEEDS_HUMAN`, active session/target 0,
  candidate/submission 0이다.

## 관측 결과

| 항목 | 결과 |
| --- | --- |
| cycle | `MC-68dc3dd8252c526ba4cb7bda` |
| 시작 | `2026-07-30T12:21:14Z` |
| 완료 | `2026-07-30T12:35:17Z` |
| wall time | 14분 3초 |
| Captain | Sol Ultra, completed |
| worker wave | Recon/Specialist/Extractor, 모두 Sol Max, 3/3 completed |
| tool run | 5개: completed 3, failed 2 |
| 실제 target 응답을 보존한 tool artifact | 0 |
| proof/candidate/submission | 0/0/0 |

이번 실행은 이전 `zone`의 빈 command contract failure와 달리 cycle 전체가
완료됐다. Captain은 adapter 결과가 target 관측이 아님을 정확히 분리하고
`/work/zone` 정적 분석, allocator lifecycle, direct stack input,
format-string의 세 surface를 유지했다. provider 동시성 3에서 세 worker가
모두 제거되지 않고 같은 `gpt-5.6-sol`로 실행된 것도 확인했다.

## 실측 병목 1: stale adapter seed

현재 primary selector는 `zone`을 `libc-2.23.so`보다 높게 평가한다. 하지만
canonical state에는 전날 생성된 다음 terminal seed가 남아 있었고 이번
재개 cycle이 이를 먼저 실행했다.

- `checksec --file=/challenge/libc-2.23.so`
- `ctfwrap -- /challenge/libc-2.23.so`

첫 실행은 exit 0이지만 stdout/stderr가 모두 0바이트였다. 두 번째 실행은
glibc를 challenge executable처럼 실행해 exit 127과 ld.so assertion을
남겼다. 현재 selector 개선이 이미 존재해도 과거 deterministic seed ID가
terminal state에 남으면 새 plan이 등록되지 않는 것이 원인이다.

필요한 수정은 session마다 checksec을 반복하는 것이 아니다. source
manifest, selected primary hash/size, adapter spec/argv contract가 동일한
terminal evidence는 재사용하고, legacy/unbound 또는 plan mismatch일 때만
새 deterministic bound seed를 생성해야 한다.

## 실측 병목 2: shell text를 direct argv로 실행

모델은 다음 형태의 bounded command를 제안했다.

```text
python3 - <<'PY'
...
PY
```

엔진은 이를 POSIX shell script가 아니라 `shlex.split()`의 direct argv로
바꿨다. 실제 request는 `["python3", "-", "<<PY", "import", ...]`였고
stdin이 비어 Python이 exit 0, stdout 0바이트로 끝났다. 따라서 두 remote
probe는 `awaiting_evaluation`이지만 target을 관측한 유효 결과가 아니다.

동일하게 `set -u`로 시작한 multiline static command는 실행 파일 `set`을
찾으려다 exit 127이 됐다. 성공 exit code만으로 모델 action 성공을
판정해서는 안 된다는 실제 반례이기도 하다.

수정 계약은 managed-model `command`만 exact `/bin/sh -lc <script>`로
정규화하고 background-job 검사를 그 script에 적용하는 것이다. engine
adapter와 operator argv는 direct-exec 의미를 유지한다. 실행 전의 legacy
`REGISTERED` managed command도 같은 방식으로 한 번 정규화해야 한다.

## 부차 관측

새 format-string hypothesis ID가 모델 output의 이미 canonical-looking ID에
run prefix를 다시 붙여 한 번 이중 prefix됐다. 현재 cycle 안의 참조는 같은
canonical ID로 수렴해 실행을 막지는 않았지만 context 품질과 장기 ID
boundedness를 해친다. local ID와 canonical ID의 경계를 별도 회귀로
고정해야 한다.

## 정본 증거

| 증거 | 경로 |
| --- | --- |
| canonical state | `.ctfos/contests/NYU_PWN_V20250206_PASS2/challenges/pwn/nyu-pwn-01/state.json` |
| stale metadata request | `runs/20260730-122116-tool-E-adapter-pwn-binary_metadata-15e2b2b1/request.json` |
| stale baseline request/result | `runs/20260730-122116-tool-E-adapter-pwn-runtime_baseline-675b9fcf/{request,result}.json` |
| Captain result | `runs/MR-21d7baa760d3559397e83f4e/attempt-1-output.json` |
| no-op remote request/result | `runs/20260730-123514-tool-E-MR-21d7baa760d3559397e83f4e-2-acd06aa0/{request,result}.json` |
| failed multiline static request/result | `runs/20260730-123516-tool-E-MR-2ba334aefe9558d98b75f414-2-e9529085/{request,result}.json` |

표의 run 경로는 위 canonical state와 같은 challenge directory 기준이다.
raw output은 이 문서에 복제하지 않고 bounded artifact와 exact pointer만
남긴다.
