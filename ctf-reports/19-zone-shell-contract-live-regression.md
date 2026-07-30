# 19. Zone shell-contract live regression

**기록일:** 2026-07-30

**대상:** `NYU_PWN_V20250206_PASS2/pwn/nyu-pwn-01`

**실행 코드 기준:** `928e8c8`

**판정:** stale managed remote action retirement, current adapter seed binding,
managed POSIX shell contract, Captain + 3-worker wave, challenge-scoped remote
allowlist가 한 실제 cycle에서 모두 작동했다. 선택된 세 실험은 전부 exit 0,
validation 통과, non-empty stdout artifact를 남겼다. 그러나 결과는 아직
semantic evaluation 전이고 deterministic Pwn gate나 proof를 통과하지
않았다. solve 개선으로 집계하지 않는다.

## 실행 경계

- 사람이 이미 선택한 `zone` 한 challenge만 실행했다.
- service는 host port 없이 internal `ctfnet`에만 기동했다.
- target generation 3만 proxy allowlist로 선택했다.
- challenge runtime은 pinned `ctf-os:core`
  `sha256:b35630c32f0ff00af423e81264a4ef57a56244fc5d0282d99aa505b4b9a6a5aa`
  를 사용했다.
- 외부 검색, write-up, hidden flag, 자동 제출은 사용하지 않았다.
- 종료 후 target generation 3을 revoke하고 service와 `ctfnet`을
  제거했다.

## 관측 결과

| 항목 | 결과 |
| --- | --- |
| session | `S-1026c8d33aa548fc93fec05df18bd001` |
| cycle | `MC-2927bc0a2bf050239fc90d97` |
| 시작 | `2026-07-30T14:42:07Z` |
| cycle 완료 | `2026-07-30T14:56:38Z` |
| Captain | Sol Ultra, contract valid, completed |
| worker wave | Recon/Specialist/Extractor, Sol Max, 3/3 contract valid, completed |
| 선택된 action | 3개 |
| tool result | 3/3 completed, exit 0, timed_out false, validation true |
| action 상태 | 3/3 `awaiting_evaluation` |
| candidate/submission | 0/0 |
| 실행 직후 상태 | rev 97 `STALLED` |
| 정리 후 상태 | rev 98 `PAUSED`, resume status `STALLED`, active target 0 |

provider 동시성 한계 때문에 논리 wave가 줄지 않았다. Recon, Specialist,
Extractor는 같은 snapshot revision 84에서 독립 컨텍스트로 실행됐고 모두
결과 계약을 통과했다.

## 앞선 두 병목의 회귀 결과

### stale action과 adapter source binding

generation 2에 묶여 있던 과거 managed remote action은 sandbox 실행 전에
`stale_managed_remote_binding_retired`로 취소됐다. 새 adapter plan은
`libc-2.23.so`가 아니라 `zone`을 primary source로 선택했고, SHA-256
`6d5c7a103e6cc251bd2cb18dc4e36eb680e55720cf8af9ad035672736190cffd`,
size 31,112 bytes에 결속됐다.

### managed shell contract

선택된 세 action은 모두 `managed_command_protocol=posix_sh_lc_v1`이었고
실제 request argv의 처음 두 원소는 exact `/bin/sh`, `-lc`였다. heredoc과
다중 shell 문장이 direct argv로 잘못 분해되던 이전 현상은 재발하지 않았다.

| experiment | target | stdout bytes | stdout SHA-256 |
| --- | --- | ---: | --- |
| `E-MR-8a0eb352face52ecb4eea052-1` | generation 3 | 334,796 | `1f6e9c035ea4c5f610f6e74b18f03c800ffd7e23cf998d212a67631dd2565a2e` |
| `E-MR-dfb7eeaa06a3541aab87fbcc-1` | local | 31,252 | `1037cb96688241f9e30b194058e6f7382d53f8e2d028435bc3bc418851b7c62a` |
| `E-MR-d0c3870f7926584b8a586a37-1` | local | 185,456 | `6c2781300c3a5b38b61e6b736bd02df174a176083da142974847439616f757db` |

non-empty artifact는 실행이 실제로 일어났다는 증거이지 취약점이나 solve의
증거는 아니다. 세 결과 모두 evaluator가 아직 keep/drop oracle을
적용하지 않았으므로 fact, gate pass, candidate, proof로 승격하지 않았다.

## 새 실측 병목: sandbox-local locator 충돌

최종 `STALLED`는 모델 실패나 반복 command가 아니라
`same_locator_artifact_churn` 신호에서 발생했다. 서로 다른 tool run의
snapshot artifact는 서로 다른 canonical path, artifact ID, SHA-256을
가졌지만 원본 sandbox locator는 모두 다음과 같았다.

```text
.ctf/runs/run-00000001/stdout.log
```

각 challenge-scoped sandbox가 자체 run counter를 1부터 시작하므로 이
locator는 전역 artifact identity가 아니다. stall detector가 canonical
snapshot identity나 content hash 대신 sandbox-local locator만 비교해
서로 다른 관측을 같은 위치의 artifact churn으로 오판했다. rev 94에서
검사한 서로 다른 두 tool run 뒤 challenge를 `STALLED`로 전환했다.

수정 조건은 다음과 같다.

1. churn identity는 최소한 producer run ID + canonical snapshot path/hash에
   결속한다.
2. 서로 다른 sandbox의 동일 local locator만으로 stall 신호를 만들지 않는다.
3. selected-action wave의 stall 판정은 개별 action commit마다가 아니라
   bounded wave가 모두 commit된 뒤 한 번 수행한다.
4. 동일 canonical artifact를 내용 변화 없이 반복한 실제 churn은 계속
   감지한다.

## 아직 증명하지 않은 것

- 결과의 semantic evaluation과 hypothesis keep/drop
- Pwn D→V→L/N/A→P→E gate 전진
- candidate 또는 proof
- hypothesis ID 정규화의 신규-ID live 회귀
- 동일 조건의 2/3 반복 성공

이번 cycle은 실행 하네스의 두 병목을 닫았음을 보여 주지만 solve 성능
표본은 아니다. 다음 live 재개는 locator 충돌 수정 후 이 세
`awaiting_evaluation` 결과를 먼저 소비하고, sandbox 실행을 불필요하게
반복하지 않아야 한다.

## 정본 증거

모든 경로는 challenge directory 기준이다.

| 증거 | 경로 |
| --- | --- |
| canonical state | `state.json` |
| Captain result/validation | `runs/MR-8a0eb352face52ecb4eea052/{result,validation}.json` |
| Recon result/validation | `runs/MR-dfb7eeaa06a3541aab87fbcc/{result,validation}.json` |
| Specialist result/validation | `runs/MR-d0c3870f7926584b8a586a37/{result,validation}.json` |
| Extractor result/validation | `runs/MR-aced60da4c5f5545a048da7a/{result,validation}.json` |
| generation 3 tool result | `runs/20260730-145636-tool-E-MR-8a0eb352face52ecb4eea052-1-8956deef/{request,result,validation}.json` |
| local Recon tool result | `runs/20260730-145636-tool-E-MR-dfb7eeaa06a3541aab87fbcc-1-ca7fead8/{request,result,validation}.json` |
| local Specialist tool result | `runs/20260730-145636-tool-E-MR-d0c3870f7926584b8a586a37-1-2289ca30/{request,result,validation}.json` |
| bounded snapshot artifacts | `artifacts/snapshots/A-20260730-145636-tool-*.log` |

raw output은 이 문서에 복제하지 않았다. 해석이 필요할 때 canonical state의
artifact ID, exact path, size, hash로 bounded snapshot을 다시 연다.
