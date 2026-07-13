# CTF-OS

CTF-OS는 사용자가 직접 연 Sol 세션을 위한 로컬 CTF 분석 도구입니다. Python은 `contest.md` 파싱, 안전한 문제 파일 준비, Docker 격리, 증거 기록, 플래그 검증만 수행하며 모델을 실행하지 않습니다.

## 운영 흐름

```text
문제 파일 + contest.md 작성
→ 사람이 Sol 세션에서 intake 요청
→ 사람이 새 Sol 세션에서 문제 선택 및 solve 요청
→ Sol swarm/race가 검증된 플래그 후보 제공, 사람 제출
```

사용자가 준비할 것은 `incoming/<대회명>/contest.md`와 카테고리별 문제 파일뿐입니다.

```text
incoming/<대회명>/
  contest.md
  pwn/<문제명>/ 또는 <문제명>.zip
  web/<문제명>/
  rev/  crypto/  forensic/  misc/  cloud/
```

권장 manifest:

```markdown
# 대회명: SCA CTF 2026

- 날짜: 2026-07-19
- 플래그 형식: SCA{...}

## 문제 목록

### pwn/NBB
- 점수: 500
- 설명: 문제 원문 설명
- 원격: nc challenge.example 31337
- 힌트: 선택사항
```

저장소 루트에서 Sol 세션을 열고 `intake 해라`라고 요청합니다. 완료 목록에서 문제를 고른 뒤 그 세션을 닫고 새 Sol 세션을 열어 `1번 문제 풀어라` 또는 `pwn/NBB 풀어라`라고 요청합니다.

Intake 결과는 `output/<contest>/intake.json`과 `INTAKE.md`에 저장됩니다. 문제별 solve 결과에는 context, state, findings, evidence, exploit, reproduce script, result가 필요한 만큼 생성됩니다.

Sandbox 기본 이미지는 다음처럼 한 번 빌드합니다.

```bash
docker build -f sandbox/Dockerfile.sandbox -t ctf-os-sandbox:latest .
```

무거운 도구는 `--build-arg CTF_OS_PROFILE=rev-heavy`, `crypto-heavy`, `forensic-heavy`로 필요할 때만 빌드합니다. 네트워크는 manifest에 선언된 public TCP 목적지로만 제한되며, HTTP(S)는 IP/port와 hostname mapping으로 제한됩니다. 공유 IP의 다른 virtual host까지 암호학적으로 구분하는 egress proxy는 구현하지 않았습니다.

플래그 제출은 항상 사람이 직접 수행합니다.
