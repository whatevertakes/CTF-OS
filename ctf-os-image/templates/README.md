# CTF-OS 풀이 템플릿

이 디렉터리는 풀이 엔진이 문제 유형에 맞는 작은 시작점을 `/work`로 복사해
수정할 수 있도록 제공한다. 입력은 읽기 전용 `/challenge`에서 읽고, 생성 파일은
항상 `/work/<category>` 아래에 둔다. 템플릿은 플래그를 제출하지 않으며 API 키나
외부 LLM을 사용하지 않는다.

```bash
cp -a /opt/ctf-templates/pwn /work/pwn-template
python3 /work/pwn-template/solve.py /challenge/chall
```

| 카테고리 | 파일 | 용도 |
|---|---|---|
| `web` | `request.py`, `browser.py`, `active_probe.py` | 크기·전체 deadline 제한 HTTP/browser 및 bounded race/OOB transport |
| `pwn` | `inspect.sh`, `solve.py`, `qemu-headless.sh` | ELF 기본 점검, bounded pwntools 골격, network/KVM 없는 TCG system-emulation 실행 |
| `rev` | `analyze.sh`, `angr_solve.py` | 문자열·한글·바이너리 메타데이터 수집과 심볼릭 stdin 탐색 |
| `crypto` | `rsa.sage` | JSON RSA 매개변수로 개인 지수/정확한 저지수 근 공격 시도 |
| `forensic` | `triage.sh`, `evidence_index.py`, `browser_timeline.py` | typed evidence 분류와 EVTX·Registry·Prefetch·E01·Office/PDF·SQLite/browser timeline 분기 |
| `misc` | `decode.py` | hex/base64/URL/ROT13/압축을 노드·파일·누적 byte budget 안에서 재귀 디코딩 |

빠른 사용 예:

```bash
python3 /opt/ctf-templates/web/request.py \
  'http://target:8080/' --header 'Accept: application/json' \
  --session attacker --timeout 15 --max-bytes 16777216 \
  --max-request-bytes 16777216
ctf-browser 'http://target:8080/' --session attacker \
  --timeout 20 --screenshot
ctf-web-probe race 'http://target:8080/claim' --session attacker \
  --data-file /challenge/request.bin --concurrency 4 --attempts 2

bash /opt/ctf-templates/pwn/inspect.sh /challenge/chall
python3 /opt/ctf-templates/pwn/solve.py /challenge/chall \
  --wait 2 --max-payload-bytes 4194304 --max-transcript-bytes 16777216
/opt/ctf-templates/pwn/qemu-headless.sh --timeout 60 \
  qemu-system-x86_64 -machine pc -kernel /challenge/bzImage \
  -initrd /challenge/initramfs.cpio.gz -append 'console=ttyS0'

bash /opt/ctf-templates/rev/analyze.sh /challenge/program
angr-python /opt/ctf-templates/rev/angr_solve.py \
  /challenge/program --find 0x401234 --avoid 0x401111

sage /opt/ctf-templates/crypto/rsa.sage /challenge/params.json
bash /opt/ctf-templates/forensic/triage.sh /challenge/evidence
/opt/ctf-templates/forensic/browser_timeline.py \
  /challenge/History --max-rows 1000
python3 /opt/ctf-templates/misc/decode.py /challenge/blob \
  --max-bytes 16777216 --max-total-bytes 67108864
```

이미지 안에서 카테고리별 준비 도구를 확인할 때는 개별 취약점 키워드를
매핑하지 않고 실제 manifest를 조회한다. `toolbox`는 선택 카테고리와 공용
system/orchestration/한글 도구만 보여 주며 도구를 자동 실행하지 않는다.

```bash
ctf-tools toolbox reversing
ctf-tools toolbox digital-forensics
ctf-tools search prefetch
ctf-tools info avr-gcc
```

로컬 SQLite handout은 raw `sqlite3` shell이나 DB daemon 대신 immutable
read-only helper로 본다. helper는 symlink/특수 파일, write/DDL/ATTACH,
extension loading, 무제한 재귀 query를 거부하고 row/cell/output/deadline을
제한한다. 원격 SQL injection은 이 helper의 역할이 아니며 선택된 target
allowlist를 거치는 HTTP/browser 도구로만 검증한다.

```bash
ctf-sqlite-readonly /challenge/app.db --schema
ctf-sqlite-readonly /challenge/app.db \
  'SELECT id,username FROM users ORDER BY id' --max-rows 200
```

AVR은 `avr-gcc`, `avr-objdump`, `avr-gdb`, `simavr`로 classic AVR firmware를
compile/disassemble/simulate할 수 있다. AArch64·ARM·MIPS/MIPSel·RISC-V는
cross compiler와 정적 QEMU user runtime을 함께 제공한다. generic `d8`은
문제별 V8 revision/build flag를 재현하지 못하므로 제공·광고하지 않으며,
kernel/SMM handout은 `qemu-headless.sh`의 TCG·network-none 기본값을 사용한다.
KVM은 이 스크립트에서 켤 수 없고 engine의 명시적 KVM lease가 필요하다.

`web/request.py --timeout`은 단일 socket read timeout이 아니라 연결부터
drip-feed 응답 수신까지 포함하는 monotonic 전체 deadline이다.
`--session attacker|user|admin`은 역할별 쿠키 jar를 격리하고 request와 browser
실행을 role 표시가 있는 `/work/web/timeline.json`의 한 타임라인으로 묶는다.
쿠키·Authorization·CSRF/JWT 값은 private jar에만 두며 타임라인과 응답
metadata에는 이름과 생성·변경·삭제만 남긴다.
`web/browser.py`도 Chromium 시작·탐색·추가 대기를 하나의 전체 deadline으로
제한한다. deadline 뒤 정리가 멈추면 격리된 브라우저 session의 Node·Chromium
프로세스를 강제 종료한다. 렌더링된 HTML과 콘솔 이벤트를 제한된 크기로 저장하며,
`--full-page`는 캡처 전에 높이와 전체 pixel 수를 검사하고 고정된 CDP clip만
캡처한다. PNG도 `--max-screenshot-bytes`를 넘으면 게시하지 않는다.
`misc/decode.py`의 `--max-total-bytes`는 원본과 모든 변환 결과가 queue에 들어간
누적 byte 수를 제한한다. `pwn/solve.py --wait`는 연결 timeout인 동시에 transcript
수신 전체 deadline이며, 지속적으로 출력하는 대상도 `--max-transcript-bytes`에서
중단한다. 파일 입력은 symlink를 따라가지 않고 같은 file descriptor에서 제한
크기만 읽는다. Python 템플릿의 결과물은 검증한 category directory descriptor에
임시 regular file로 쓴 뒤 atomic replace하며, 기존 결과물 symlink를 따라가
외부 파일을 덮어쓰지 않는다. shell 템플릿은 symlink·비정규 결과 경로를 명시적으로
거부한다.

`forensic/triage.sh`는 source를 변경하지 않고 각 parser의 stdout/stderr를
파일당 제한된 artifact로 남긴다. Chrome `History`와 Firefox `places.sqlite`의
timeline은 UTC로 정규화되며 WAL sidecar가 보이면 읽지 않았다는 경고를 결과에
명시한다. Prefetch는 `sccainfo`, event log는 `evtxinfo`/`evtxexport`, Registry는
`regfinfo`/`regfexport`, EWF는 `ewfinfo`/`ewfverify`로 분기한다.

`angr`, SageMath, 디컴파일, 크래킹처럼 오래 걸릴 수 있는 작업은 실행 엔진에서
시간 제한을 주거나 `ctf-bg`로 시작한다. 각 템플릿을 문제에 맞게 `/work`에
복사한 뒤 주소, 프로토콜, 공격 로직을 수정하는 것이 기본 사용 방식이다.
