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
| `web` | `request.py`, `browser.py` | 크기·전체 deadline 제한을 둔 HTTP 요청과 headless Chromium 렌더링 |
| `pwn` | `inspect.sh`, `solve.py` | ELF 기본 점검과 payload/transcript 크기·수신 deadline을 둔 pwntools 골격 |
| `rev` | `analyze.sh`, `angr_solve.py` | 문자열·한글·바이너리 메타데이터 수집과 심볼릭 stdin 탐색 |
| `crypto` | `rsa.sage` | JSON RSA 매개변수로 개인 지수/정확한 저지수 근 공격 시도 |
| `forensic` | `triage.sh` | 메타데이터·문자열·HWP·한글 OCR·PCAP 기본 분류 |
| `misc` | `decode.py` | hex/base64/URL/ROT13/압축을 노드·파일·누적 byte budget 안에서 재귀 디코딩 |

빠른 사용 예:

```bash
python3 /opt/ctf-templates/web/request.py \
  'http://target:8080/' --header 'Accept: application/json' \
  --session attacker --timeout 15 --max-bytes 16777216 \
  --max-request-bytes 16777216
ctf-browser 'http://target:8080/' --session attacker \
  --timeout 20 --screenshot

bash /opt/ctf-templates/pwn/inspect.sh /challenge/chall
python3 /opt/ctf-templates/pwn/solve.py /challenge/chall \
  --wait 2 --max-payload-bytes 4194304 --max-transcript-bytes 16777216

bash /opt/ctf-templates/rev/analyze.sh /challenge/program
angr-python /opt/ctf-templates/rev/angr_solve.py \
  /challenge/program --find 0x401234 --avoid 0x401111

sage /opt/ctf-templates/crypto/rsa.sage /challenge/params.json
bash /opt/ctf-templates/forensic/triage.sh /challenge/evidence
python3 /opt/ctf-templates/misc/decode.py /challenge/blob \
  --max-bytes 16777216 --max-total-bytes 67108864
```

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

`angr`, SageMath, 디컴파일, 크래킹처럼 오래 걸릴 수 있는 작업은 실행 엔진에서
시간 제한을 주거나 `ctf-bg`로 시작한다. 각 템플릿을 문제에 맞게 `/work`에
복사한 뒤 주소, 프로토콜, 공격 로직을 수정하는 것이 기본 사용 방식이다.
