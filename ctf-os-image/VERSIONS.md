# CTF-OS 버전 검증

초기 검증일: 2026-07-27 (Asia/Seoul)
Managed Rev 재빌드 검증일: 2026-07-30 (Asia/Seoul)

GitHub 항목은 각 저장소의 `GET /repos/{owner}/{repo}/releases/latest` 응답에서
`draft=false`, `prerelease=false`인 릴리스와 실제 자산명을 확인했다. 아래 직접
다운로드 URL은 `curl -fsIL`로 리다이렉트를 따라간 최종 응답이 HTTP 200인지
검증했다.

## 릴리스 ARG

| ARG | 저장소 | 기존 값 | 확인한 최신 안정 버전 | 실제 Linux amd64 자산 | Dockerfile URL | 최종 HTTP |
|---|---|---:|---:|---|---|---:|
| `PWNDBG_VER` | [pwndbg/pwndbg](https://github.com/pwndbg/pwndbg) | `2025.08.06` | `2026.02.18` | `pwndbg_2026.02.18_amd64.deb` | [확인](https://github.com/pwndbg/pwndbg/releases/download/2026.02.18/pwndbg_2026.02.18_amd64.deb) | 200 |
| `PWNINIT_VER` | [io12/pwninit](https://github.com/io12/pwninit) | `3.3.1` | `3.3.1` | `pwninit` | [확인](https://github.com/io12/pwninit/releases/download/3.3.1/pwninit) | 200 |
| `GHIDRA_VER` / `GHIDRA_DATE` | [NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra) | `11.3.2` / `20250415` | `12.1.2` / `20260605` | `ghidra_12.1.2_PUBLIC_20260605.zip` | [확인](https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.2_build/ghidra_12.1.2_PUBLIC_20260605.zip) | 200 |
| `JADX_VER` | [skylot/jadx](https://github.com/skylot/jadx) | `1.5.1` | `1.5.6` | `jadx-1.5.6.zip` | [확인](https://github.com/skylot/jadx/releases/download/v1.5.6/jadx-1.5.6.zip) | 200 |
| `APKTOOL_VER` | [iBotPeaches/Apktool](https://github.com/iBotPeaches/Apktool) | `2.11.1` | `3.0.3` | `apktool_3.0.3.jar` | [확인](https://github.com/iBotPeaches/Apktool/releases/download/v3.0.3/apktool_3.0.3.jar) | 200 |
| `CFR_VER` | [leibnitz27/cfr](https://github.com/leibnitz27/cfr) | `0.152` | `0.152` | `cfr-0.152.jar` | [확인](https://github.com/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar) | 200 |
| `GORESYM_VER` | [mandiant/GoReSym](https://github.com/mandiant/GoReSym) | `2.7.3` | `3.4` | `GoReSym-linux.zip` | [확인](https://github.com/mandiant/GoReSym/releases/download/v3.4/GoReSym-linux.zip) | 200 |
| `FFUF_VER` | [ffuf/ffuf](https://github.com/ffuf/ffuf) | `2.1.0` | `2.2.1` | `ffuf_2.2.1_linux_amd64.tar.gz` | [확인](https://github.com/ffuf/ffuf/releases/download/v2.2.1/ffuf_2.2.1_linux_amd64.tar.gz) | 200 |
| `NUCLEI_VER` | [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) | `3.3.9` | `3.11.0` | `nuclei_3.11.0_linux_amd64.zip` | [확인](https://github.com/projectdiscovery/nuclei/releases/download/v3.11.0/nuclei_3.11.0_linux_amd64.zip) | 200 |
| `DALFOX_VER` | [hahwul/dalfox](https://github.com/hahwul/dalfox) | `2.11.0` | `3.1.2` | `dalfox-v3.1.2-linux-x86_64.tar.gz` | [확인](https://github.com/hahwul/dalfox/releases/download/v3.1.2/dalfox-v3.1.2-linux-x86_64.tar.gz) | 200 |
| `FEROX_VER` | [epi052/feroxbuster](https://github.com/epi052/feroxbuster) | `2.11.0` | `2.13.1` | `x86_64-linux-feroxbuster.tar.gz` | [확인](https://github.com/epi052/feroxbuster/releases/download/v2.13.1/x86_64-linux-feroxbuster.tar.gz) | 200 |
| `YSOSERIAL_VER` | [frohoff/ysoserial](https://github.com/frohoff/ysoserial) | `0.0.6` | `0.0.6` | `ysoserial-all.jar` | [확인](https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar) | 200 |
| `BKCRACK_VER` | [kimci86/bkcrack](https://github.com/kimci86/bkcrack) | 없음 | `1.8.1` | `bkcrack-1.8.1-Linux-x86_64.tar.gz` | [확인](https://github.com/kimci86/bkcrack/releases/download/v1.8.1/bkcrack-1.8.1-Linux-x86_64.tar.gz) | 200 |

GoReSym 3.4는 기존의 버전 포함 tarball 대신 `GoReSym-linux.zip`을 배포한다.
압축 내부 파일은 루트의 `GoReSym` 하나다. Dalfox 3.1.2는 자산명에 `v`와
`x86_64`가 들어가며, 바이너리가 `dalfox-v3.1.2-linux-x86_64/dalfox` 아래에
있어 `--strip-components=1`로 푸는 방식으로 수정했다.

## 추가 확인

| 항목 | 결과 | Dockerfile 반영 |
|---|---|---|
| pwndbg deb 내용 | 170,623,162바이트 공식 deb를 `dpkg-deb -c`로 확인. `gdbinit.py`는 현재 `/usr/lib/pwndbg-gdb/lib/python3.13/site-packages/pwndbginit/gdbinit.py`. 이름이 정확히 `pwndbg-gdb`인 실행 파일은 없고 `/usr/bin/pwndbg`가 `/usr/lib/pwndbg-gdb/bin/pwndbg`를 가리킴 | 경로를 하드코딩하지 않고 `find`로 `*/pwndbginit/gdbinit.py`와 번들 진입점을 찾음 |
| pwndbg 로드 | 공식 `ubuntu:24.04`에서 시스템 `/usr/bin/gdb -batch -ex 'vmmap'`은 `ModuleNotFoundError: pwndbginit`과 undefined command로 실패. `/usr/bin/pwndbg -batch -ex 'vmmap'`은 명령을 정상 등록하고 종료 코드 0 | 빌드 중 시스템 gdb를 먼저 검사하고 실패하면 `/usr/lib/.../pwndbg-gdb/bin/pwndbg`를 `/usr/local/bin/gdb`로 연결. 이후 실제 `gdb -batch -ex 'vmmap'` 재검증 |
| Rust 툴체인 | [rustup](https://rustup.rs/) `stable`, `minimal` 프로필로 실제 설치 시 `rustc 1.97.1`, `cargo 1.97.1`. 이 cargo로 `rustfilt`와 `ciphey 0.12.0` 컴파일·설치 성공 | apt cargo 폴백 제거, `/root/.cargo/bin`을 `PATH`에 추가, cargo 오류를 숨기거나 건너뛰지 않음 |
| 압축 해제 실행 권한 | GoReSym과 nuclei의 ZIP 내부 파일은 실행 비트 보존을 전제로 할 수 없음 | 두 바이너리에 명시적으로 `chmod +x` |
| `/work` 볼륨 | Dockerfile의 `VOLUME`은 런처의 명시적 bind mount와 이미지 레이어 검증을 방해할 수 있음 | `VOLUME ["/work"]` 제거 |
| Zeek OBS Noble 저장소 | [`xUbuntu_24.04/`](https://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/), [`Release`](https://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/Release), [`Release.key`](https://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/Release.key) 모두 HTTP 200 | 저장소를 HTTPS로 바꾸고 키 URL을 동일한 정규 경로로 통일 |
| Ares 설치법 | [bee-san/Ares](https://github.com/bee-san/Ares)의 배포 패키지와 바이너리 이름은 둘 다 `ciphey`. crates.io의 최신 공개 버전은 `0.12.0`이고 README 설치법은 `cargo install ciphey`. 이 버전은 `--version` CLI 옵션은 제공하지 않음 | `cargo install --locked --version 0.12.0 --root /usr/local ciphey`. 실행 명령은 `ciphey` |
| ILSpyCmd 런타임 | 최신 10.1.1.8388 NuGet 패키지는 `tools/net10.0`만 포함해 .NET 8 SDK에서 설치 불가. 9.1.0.7988은 `tools/net8.0`을 포함하며 설치 및 `--version` 실행 성공 | `ILSPYCMD_VER=9.1.0.7988`로 고정하고 빌드 중 실제 버전 검사 |
| flatter | upstream 설치 문서의 필수 패키지에 `libopenblas-dev`가 있으며, 기존 실패는 CMake의 `Could NOT find BLAS` | `libopenblas-dev` 추가, 검증한 커밋 `d2b8026f29b4a69e987b15d4b240f8a5053275d3` 고정, `flatter -h` 검사 |
| John the Ripper | `/opt/john/run/john`은 정상이나 PATH 검색으로 `john`만 실행하면 `$JOHN` 홈을 찾지 못함 | 절대 경로로 원본 바이너리를 실행하는 `/usr/local/bin/john` 래퍼와 빌드 중 `--list=build-info` 검사 |
| ML Python 진입점 | venv의 Python을 다시 심볼릭 링크하면 Python이 `/usr/bin/python3`까지 링크를 해석해 venv를 인식하지 못하고 `torch` import 실패 | `/opt/venvs/ml/bin/python`을 `exec`하는 셸 래퍼로 교체하고 빌드 중 `torch` import 검사 |
| angr Python 진입점 | ML Python과 같은 인터프리터 심볼릭 링크 문제로 `angr-python`에서 venv가 해제되어 `import angr` 실패 | `/opt/venvs/angr/bin/python`을 `exec`하는 셸 래퍼로 교체하고 빌드 중 `angr` import 검사 |
| 문서 분석 CLI | `oleid`, `olevba`, `peepdf`는 docs venv에만 있어 이미지 `PATH`에서 발견되지 않았음 | venv console script를 `/usr/local/bin`에 연결하고 manifest에서 실제 실행 가능 여부 확인 |
| PyInstaller 추출기 | upstream `pyinstxtractor.py`는 shebang과 실행 비트가 없어 `command -v`로 찾더라도 직접 실행 불가 | Python 3 shebang과 실행 비트를 부여해 CLI로 노출 |
| 무인 실행 guard | `ciphey`는 무인 no-arg에서 panic/core dump, `clamscan`은 현재 디렉터리 전체 스캔, `ngrep`·`tcpdump`·`mitmdump`는 캡처/프록시 대기, `photorec`·`testdisk`는 TUI에 진입, 일부 QEMU system 명령은 모니터에서 대기 | 원본을 PATH 밖의 `*.real`로 보존하고 `/usr/local/bin` guard를 노출. no-arg는 usage와 종료 코드 2, PhotoRec/TestDisk는 `/cmd`(TestDisk는 `/list`도 허용) 기반 무인 모드만 전달 |
| nuclei 템플릿 | 검증 시점 `main`은 `4ccef9ea7c907d917b1608d60d73b12823bdfdf5` | 해당 커밋을 shallow fetch하고 VCS 메타데이터를 제거 |
| 오프라인 자산 실패 처리 | rockyou 아카이브 부재와 Volatility 심볼 다운로드 실패가 기존에는 성공으로 처리될 수 있었음 | 필수 아카이브 존재를 검사하고 세 플랫폼 심볼 중 하나라도 실패하면 빌드 실패 |
| rockyou 변형 | SecLists에는 `rockyou-withcount.txt.tar.gz`와 일반 `rockyou.txt.tar.gz`가 함께 있어 첫 glob 결과가 풀이 도구가 기대하는 형식과 다를 수 있음 | 일반 `rockyou.txt`를 명시적으로 추출하고 count 포함 변형은 제거 |
| Volatility 심볼 전송 | 839,727,133-byte Windows ZIP 전송이 중간 reset으로 끊기는 것을 실제 재현 | BuildKit cache에 부분 파일을 보존하고 Range 재개, 저속 연결 중단, 재시도, 세 ZIP의 `unzip -t` 검증을 모두 강제 |

## 기능 공백 보강 검증

| 항목 | 고정 버전/커밋 | 실제 확인 |
|---|---|---|
| main Python 복구 | `cysignals 1.12.6`, BeautifulSoup `4.15.0`, lxml `6.1.1`, h2 `4.4.0`, websockets `16.1.1` | 기존 `fpylll` import 복구와 여섯 모듈 동시 import 성공 |
| HTTP/2 race 도구 | `h2spacex 1.2.2` | 기본 의존성 설치가 Scapy를 `2.5.0`으로 내리는 것을 재현. `brotlipy 0.7.0`을 명시하고 `--no-deps`로 설치해 기존 Scapy `2.7.0` 유지 |
| Sage PyCryptodome | `pycryptodome 3.23.0` | `/opt/mamba/envs/sage/bin/python`에서 `long_to_bytes` import 성공 |
| cuso | `fb2747d2105a8e48499bf10a3a717cf80c14d079` | Sage 환경 설치와 upstream RSA 부분 인수분해 예제 성공 |
| [gf2bv](https://github.com/maple3142/gf2bv) | `4357db5cae0dc1213526b93180b9a26f14a91070` | main 환경 설치와 `LinearSystem` 생성 성공 |
| ropr | `cf2e2d384e67328cd9d27537172927ed9a27e5ab`, `0.2.27` | `cargo install --locked` 성공, `/bin/true` gadget 스캔 완료 |
| hash_extender | `f00b1a02eca02b0907e26726f7efe437bc396aa4` | README의 MD5 길이 확장 벡터가 기대 서명 `6ee582a1669ce442f3719c47430dadee` 생성 |
| bkcrack | `1.8.1`, SHA-256 `45dc7d81adbaaad5c0aa2d8615ea920fd08b732fda1ea945504e0a3e8dc1d2ab` | 공식 Linux x86-64 자산 해시와 `--version` 확인 |
| Wine | Ubuntu `9.0~repack-4build3` | `wine32:i386`와 `wine64`를 함께 설치하고 두 loader의 `--version` 실행 성공 |

`h2spacex`는 CLI entry point가 없는 라이브러리이므로 `web-python`으로,
`cuso`와 `gf2bv`는 각각 `sage-python`과 `crypto-python`으로 노출한다.
Playwright는 전체 Chromium 대신 headless shell만 설치하고 `playwright`,
`pw-python`, 제한형 `ctf-browser` 진입점을 함께 제공한다.

## PyTorch CUDA 채널

[`download.pytorch.org/whl/`](https://download.pytorch.org/whl/) 루트에서 현재
노출되는 `cu1xx` 디렉터리는 다음과 같다.

`cu100`, `cu101`, `cu102`, `cu110`, `cu111`, `cu113`, `cu115`, `cu116`,
`cu117`, `cu118`, `cu121`, `cu124`, `cu126`, `cu128`, `cu129`, `cu130`,
`cu132`.

공식 PyTorch 설치 선택기의 현재 안정 CUDA 선택지는 12.6, 13.0, 13.2다.
명시적인 인덱스 URL을 제공하며 가장 최신인 `cu132`로 고정했다.

| 검증 | 결과 |
|---|---|
| Python 3.12 의존성 해석 | `torch==2.13.0+cu132`, `torchvision==0.28.0+cu132`로 해결 |
| 전체 설치 | `uv pip install torch torchvision --index-url https://download.pytorch.org/whl/cu132` 성공 |
| 설치된 venv 크기 | `4.6G` |
| GPU 노출 | `torch.cuda.is_available() == True` |
| GPU 숨김 (`CUDA_VISIBLE_DEVICES=''`) | import 및 CPU 텐서 연산 성공, `torch.cuda.is_available() == False` |

WSL2 호스트에 NVIDIA Container Toolkit `1.19.1`을 공식 apt 저장소에서
설치하고 Docker runtime과 CDI를 구성했다. `--gpus all`과
`--device nvidia.com/gpu=all` 양쪽에서 RTX 4060 Ti CUDA 텐서 연산을
검증했다. Hashcat이 요구하는 비버전 `libnvrtc.so` 이름은 PyTorch cu132
휠의 `libnvrtc.so.13`과 `libcudart.so.13`을
`/usr/local/lib/ctf-cuda`에 연결한다. 같은 컨테이너에서 `hashcat -I`가
CUDA 13.1의 RTX 4060 Ti를 backend device로 인식했다.

## Ghidra 12.1.2

공식 572,803,866바이트 배포 ZIP 자체와 그 안의 설정·휠을 확인했다.

| 검증 | 결과 | Dockerfile 반영 |
|---|---|---|
| JDK 요구사항 | `Ghidra/application.properties`의 `application.java.min=21`, max는 비어 있음. 공식 Getting Started도 64비트 JDK 21 요구 | 기존 `openjdk-21-jdk-headless`면 충분. 압축 해제 후 min 값이 21인지 빌드 중 검사 |
| PyGhidra 동봉 여부 | `Ghidra/Features/PyGhidra/pypkg/dist/`에 `pyghidra-3.1.0` wheel/sdist, JPype 1.5.2 등 오프라인 의존성 포함 | PyPI 대신 `--no-index --find-links .../pypkg/dist pyghidra` 사용 |
| 동봉 PyGhidra 설치 | Python 3.12 venv에서 오프라인 설치 성공. `pyghidra.__version__ == 3.1.0` | `/opt/venvs/ghidra`에 같은 방법 적용 |

## Apktool 3.0.3

| 검증 | 결과 |
|---|---|
| JDK | v3.0.3 태그의 Gradle 설정은 `sourceCompatibility`/`targetCompatibility`와 `--release`를 모두 Java 8로 설정. Ubuntu 24.04의 OpenJDK 21에서 실제 JAR 실행 성공 |
| 기본 CLI | `--version`은 `3.0.3`; `d -h`, `b -h`에서 decode/build의 `-f`와 `-o` 확인 |
| v2 호환성 | v3는 `-api`, `--only-main-classes`, aapt1 지원을 제거했고 여러 고급 옵션의 짧은 이름을 제거함. `d`/`decode`, `b`/`build`, `-f`, `-o`는 유지 |

Dockerfile 래퍼는 인자를 그대로 JAR에 전달하므로 유지하고, 빌드 중
`java -jar apktool.jar --version`이 ARG 값과 같은지만 추가 검사한다.

## Python 패키지

| 패키지 | 확인 결과 | Dockerfile 반영 |
|---|---|---|
| `pdfid` | [PyPI](https://pypi.org/project/pdfid/)에 `1.1.3` wheel/sdist가 존재하고 Python 3.12 설치 및 `python -m pdfid --help` 성공. 단, console script는 생성하지 않음 | `/opt/venvs/docs/bin/python -m pdfid`를 호출하는 `/usr/local/bin/pdfid` 래퍼 추가 |
| `peepdf-3` | PyPI `5.3.0`, Python `>=3.9` | 기존 venv 설치 유지 |
| `pyhwp` | Python 3.12 설치는 성공하지만 선언되지 않은 런타임 의존성 `six`가 없어 `hwp5txt` import 실패. `six==1.17.0` 추가 후 CLI 실행 성공 | hwp venv에 `six`를 명시하고 빌드 중 `hwp5txt --version` 검사 |

## 무인 실행 guard

초기 `ctf-os:tools` catalog 실행 파일 123개를 각각 stdin 없이 5초 제한으로
호출했을 때 일곱 이름이 에이전트 실행 계약을 깨뜨렸다. 기능 보강 후 최종
manifest 182개(고유 이름/경로 177개)를 같은 방식으로 다시 감사해 QEMU system
명령 두 개를 추가로 확인했다.

| 실행 파일 | 원래 no-arg 동작 |
|---|---|
| `ciphey` | 입력이 없다는 Rust panic과 core dump, 종료 코드 134 |
| `clamscan` | 현재 디렉터리 전체를 재귀 스캔. `/`에서 검증 시 약 7초와 파일별 출력 발생 |
| `ngrep` | 기본 인터페이스 캡처를 시작해 20초 제한까지 종료하지 않음 |
| `tcpdump` | `any` 인터페이스 캡처를 시작해 20초 제한까지 종료하지 않음 |
| `mitmdump` | 기본 `*:8080` 프록시를 시작해 20초 제한까지 종료하지 않음 |
| `photorec` | curses 기반 대화형 복구 화면에 진입해 20초 제한까지 종료하지 않음 |
| `testdisk` | curses 기반 대화형 복구 화면에 진입해 20초 제한까지 종료하지 않음 |
| `qemu-system-mips` | 기본 모니터에 진입해 5초 제한까지 종료하지 않음 |
| `qemu-system-x86_64` | 기본 머신을 시작하고 모니터에서 5초 제한까지 종료하지 않음 |

실제 실행 파일은
`/usr/local/libexec/ctf-os/{ciphey,clamscan,ngrep,tcpdump,mitmdump,photorec,testdisk,qemu-system-mips,qemu-system-x86_64}.real`
에 보존했다. PATH의 같은 이름은 공통 guard를 가리킨다. guard는 인자가 없으면
usage를 stderr에 쓰고 종료 코드 2로 즉시 끝낸다. `photorec`는 help/version과
명시적인 `/cmd` 호출만, `testdisk`는 여기에 `/list`를 더한 호출만 허용한다.
장시간 캡처나 프록시는 명시적 인자와 `ctf-bg`를 함께 사용해야 한다.

guard가 허용한 호출은 `exec REAL "$@"`로 전달하므로 인자를 바꾸지 않는다.
tools 스테이지에서 다음을 실제 검증했다.

- 아홉 이름의 no-arg 호출은 모두 5초 이내 종료 코드 2와 usage를 반환
- 각 help/version 호출은 5초 이내 종료하고 timeout/SIGKILL 없음
- wrapper와 보존 원본의 동일 인자 실행 결과는 stdout, stderr, 종료 코드가 동일
- 1MiB 빈 이미지에 대한 `photorec /cmd ...`와 `testdisk /cmd ...`가 각각
  종료 코드 0으로 무인 완료
- manifest의 관련 10개 항목(`ciphey`는 두 카테고리)이 모두
  `/usr/local/bin/<name>`을 가리키며 `available=true`

## libc-database

upstream [`get`](https://github.com/niklasb/libc-database/blob/master/get) 스크립트는
`for category in "$@"`로 모든 인자를 순회하며, README도
`./get ubuntu debian`을 공식 예제로 제시한다. 따라서 기존의 두 인자 호출은
올바르다.

공식 `ubuntu:24.04` 컨테이너에서 upstream 스크립트를 수정하지 않고 실제
`./get ubuntu debian`을 완료했다.

| 측정 | 결과 |
|---|---:|
| 종료 코드 | 0 |
| 처리한 `Getting` 항목 | 1,272 |
| 다운로드 실패 | 0 |
| `db/` 파일 수 | 2,640 |
| `db/` 크기 | 877M |
| 저장소 전체 `du -sh` | **879M** |

첫 검증 실행에서 assets 스테이지에 없는 `binutils`, `perl`, `zstd`와 압축
해제 도구가 필요하다는 점도 확인했다. Dockerfile의 assets 패키지에
`binutils`, `file`, `perl`, `zstd`, `xz-utils`, `bzip2`를 명시하고, 긴
수집 로그는 파일로 보내 실패 시 마지막 100줄만 출력한다. 성공 시에는
`du -sh /assets/libc-database`만 빌드 로그에 출력한다.

## 오프라인 자산 통합 검증

최종 `ctf-os:assets`를 네트워크 없이 실행해 다음을 확인했다.

| 자산 | 검증 결과 |
|---|---:|
| 일반 `rockyou.txt` | 139,921,497 bytes |
| SecLists sparse 파일 | 636 |
| libc DB 파일 | 2,640 |
| nuclei YAML 템플릿 | 13,495 |
| Volatility Windows ZIP | 839,727,133 bytes, `unzip -t` 성공 |
| Volatility Linux ZIP | 2,980,184 bytes, `unzip -t` 성공 |
| Volatility macOS ZIP | 84,808,562 bytes, `unzip -t` 성공 |
| 전체 `/assets` 전개 크기 | 2,967,724,032 bytes |

`libc-database`의 `identify`와 `find`는 실행 위치를 기준으로 `db/`를
찾으므로 단순 심볼릭 링크 대신 DB 디렉터리로 이동하는 래퍼를 사용한다.
Volatility CLI도 `/opt/volatility3/symbols`를 자동 탐색하지 않으므로 최종
`vol` 래퍼가 `--symbol-dirs /opt/volatility3/symbols`를 항상 선행한다.

## Ubuntu 24.04 apt

공식 `ubuntu:24.04` 컨테이너에서 `apt-get update` 후 `apt-cache policy`로
확인했다.

| 패키지 | Candidate | 판정 | Dockerfile 처리 |
|---|---:|---|---|
| `ltrace` | `0.7.3-6.4ubuntu3` | 설치 가능 | 필수 패키지로 직접 설치 |
| `scalpel` | `1.60+git20240110.6960eb2-1build1` | 설치 가능 | 기존 apt 목록 유지 |
| `bulk-extractor` | 없음 | apt 설치 불가 | 공식 안정 릴리스 `v2.1.1`을 재귀 서브모듈과 함께 소스 빌드하고 `bulk_extractor -V` 검사 |
| `gobuster` | `3.6.0-1ubuntu0.24.04.3` | 설치 가능 | 오타가 있던 폴백을 제거하고 `gobuster` 직접 설치 |
| `dcfldd` | `1.9.1-1ubuntu2` | 설치 가능 | 기존 apt 목록 유지 |
| `peepdf-3` | 없음 | apt 설치 불가 | 기존처럼 PyPI에서 설치. PyPI `5.3.0`은 Python `>=3.9` 요구 |

### GCC multilib와 cross compiler

Ubuntu 24.04의 `gcc-13-aarch64-linux-gnu`,
`gcc-13-arm-linux-gnueabihf`, `gcc-12-mips-linux-gnu`,
`gcc-12-mipsel-linux-gnu`, `gcc-13-riscv64-linux-gnu`는 모두
`Conflicts: gcc-multilib`을 선언한다. 따라서 `gcc-multilib` 메타패키지와
cross compiler를 한 번에 요청하면 후보가 존재해도 apt가 의존성을 풀 수 없다.

실제 구현 패키지인 `gcc-13-multilib`은 이 충돌 대상이 아니다. 공식
`ctf-os:base`에서 PWN 패키지 전체를 다음 조합으로 apt 시뮬레이션한 결과
종료 코드 0으로 해결됐고, 같은 조합의 실제 설치도 성공했다.

- `gcc-13-multilib` + `libc6-dev-i386`
- aarch64, armhf, mips, mipsel, riscv64 cross GCC 전체
- arm64, armhf cross libc 개발 패키지

Dockerfile은 `gcc-multilib`만 `gcc-13-multilib`으로 바꿔 `gcc -m32`와
cross compiler를 모두 유지한다. 설치 후 최소 C 소스를 컴파일해 x86 32-bit,
aarch64, armhf, MIPS big-endian, MIPS little-endian, RISC-V 64-bit ELF
오브젝트가 모두 생성되는 것까지 확인했다.

### bulk_extractor 2.1.1 소스 빌드

공식 `v2.1.1` 태그의 설치 절차(`bootstrap.sh`, `configure`, `make`,
`make install`)를 Ubuntu 24.04 기반 `ctf-os:tools`에서 검증했다. 공식
Ubuntu 준비 스크립트의 의존성 중 이미지에 없던 `flex`, `libabsl-dev`,
`libre2-dev`, `libxml2-utils`와 EWF 입력 지원용 `libewf-dev`를 추가했다.
재귀 서브모듈을 포함한 빌드와 설치 후 `bulk_extractor -V`는
`bulk_extractor 2.1.1`을 출력했다.

## 최종 core 이미지

기능 공백 보강과 최신 scripts/templates를 포함한 `ctf-os:core`를 다시
빌드했다. 새 컨테이너의 병합 루트에서 `du -sx -B1 /`로 전개 크기를
직접 측정했으며, 크기 상한은 적용하지 않았다.

| 검증 | 결과 |
|---|---:|
| 이미지 digest | `sha256:114da21d7258593dd7db586e210ebfdf9a9b75eaa9efa16337b0dec53ad575c7` |
| Docker inspect Size | 12,501,798,267 bytes |
| 병합 루트 전개 크기 | **26,213,908,480 bytes** |
| 도구 manifest | schema v1, 182개 중 182개 사용 가능, failed 0 |
| 카테고리 수 | crypto 25, forensic 46, misc 17, pwn 28, rev 28, web 18, 나머지 20 |
| SQL 제거 | `sqlmap` venv와 CLI 없음, `sqlite3`/`mysql`/`psql` 없음, PHP DB 확장 없음 |
| 낡은 실패 상태 | 런타임 `/tools/failed.txt` 없음 |

빌드 안에서 Sage factor/LLL/cuso/PyCryptodome, main Python의
fpylll/gf2bv/HTML/HTTP2/WebSocket 모듈, CUDA PyTorch, John, Zeek,
Playwright headless Chromium을 실제 실행했다. 별도 새 컨테이너 회귀
테스트에서는 다음을 추가로 확인했다.

- 로컬 HTTP 페이지를 Chromium으로 열어 상태 200, 제목, 렌더링 HTML,
  스크린샷을 `/work/web`에 저장
- RSA 템플릿이 Sage의 `Crypto.Util.number.long_to_bytes` 경로로 평문 복구
- QCOW2 생성/조회, SquashFS 생성/조회, WAT→WASM→최적화
- Wine 32/64, Mono, ARM/MIPS/x86-64 QEMU, ropr, bkcrack 실행
- 공식 NVIDIA CDI로 RTX 4060 Ti PyTorch CUDA 연산과 Hashcat CUDA backend 실행
- manifest 182개·고유 실행 경로 177개 전부를 네트워크와 stdin 없이 호출:
  누락 0, 5초 timeout 0, crash 0
- 새 Python/Wine/QEMU 진입점의 no-arg 호출이 5초 안에 종료 코드 2 반환
- 최종 이미지의 `/usr/local/bin` 배포 스크립트와
  `/opt/ctf-templates`가 현재 `scripts/`, `templates/` 소스와 byte-for-byte
  일치

위 `sha256:114d...` 기록은 2026-07-27 이미지의 역사적 측정값이며 아래
Managed Rev primitive 재빌드로 대체됐다.

## 2026-07-30 Managed Rev proof 재빌드

`inventory_v2.py`, 그 publication dependency인 `safe_output.py`, 고정
`stdin_exec.py`를 managed capability contract에 포함한 뒤 `ctf-os:core`를
다시 빌드했다. 여기 적은 값은 registry manifest digest가 아니라 이 호스트에서
Docker가 반환한 exact local image ID다. CTF-OS의
`runtime.image_digest`도 이 값을 그대로 실행 참조로 사용한다.

| 검증 | 결과 |
|---|---:|
| exact local image ID | `sha256:bc3d595abd832e5c2e9802ad78e793ca57b94aca6135a4aa58998051970d0ba6` |
| 생성 시각 | `2026-07-30T09:47:41.419652441+09:00` |
| Docker inspect Size | 12,512,518,103 bytes |
| 병합 루트 전개 크기 | **26,249,244,672 bytes** |
| 도구 manifest | schema v1, 182개 중 182개 사용 가능, failed 0 |
| capability manifest | schema v2, 8개 중 8개 사용 가능 |
| 카테고리 수 | crypto 25, forensic 46, korean 1, misc 17, orchestration 9, pwn 28, rev 28, system 10, web 18 |

Managed Rev attestation은 다음 exact file identity를 요구한다.

| capability | contract | SHA-256 |
|---|---|---|
| `rev_inventory_v2` | `ctfos.rev.inventory` v2 | `782d41566f3a288b458ae3fdbb04a0684f281158b14286739ea3cc1ecc39daee` |
| `rev_safe_output` | `ctfos.rev.safe_output` v1 | `24fbff27464dc2ff12a754831ec87a1a8e9a0ffb4dde790bb738f83d97852951` |
| `rev_stdin_exec` | `ctfos.rev.stdin_exec` v1 | `036edb158461aa32c6688a7f33f3d523f593202409b62377288c8c8e54b45610` |

host source와 이미지 안 세 파일의 hash가 일치함을 확인했다. network-none,
read-only root, capability drop, no-new-privileges, non-root UID/GID,
read-only `/challenge`, tmpfs `/work` 조건에서 inventory v2의 stdout과
published artifact가 byte-for-byte 같았고, stdin runner가 seal한 exact
bytes를 `/challenge/cat`에 전달했다.

이미지 안 lifecycle shell tests 전체와 browser/tool/capability smoke가
통과했다. 추적 C fixture를 host에서 컴파일한 뒤 실제
`DockerSandboxBackend.run_clean_proof`로 서로 다른 clean workspace 여섯
개를 실행해 다음도 확인했다.

- 동일 accepted input positive 3회는 exit 0과 exact candidate를 보존
- `xor-first`, `xor-last`, `truncate` control은 exit 7, `rejected`이고
  candidate가 없음
- 여섯 run 모두 network `none`, complete/non-truncated stdout/stderr,
  null capture/orchestration error와 exact stored byte metadata
- `.proof-live` residue 없음

`.venv/bin/python -m ctf_os pin-image` 뒤 ignored local
`.ctfos/engine.toml`에 위 exact ID가 기록됐다. `ctfos doctor`는
`pin_status: matched`, warning 없음이었고 host capability preflight도
필수 8개, 누락 0, attestation error 0으로 통과했다.

이 local ID pin은 이미 빌드된 runtime의 반복 실행을 고정한다. Ubuntu apt,
upstream download와 일부 mutable build input까지 content-addressed하게
고정한 globally reproducible build를 뜻하지는 않는다. tag를 다시 빌드하면
exact ID smoke, pin과 preflight를 다시 수행해야 한다.

## 보장 범위

위 검증은 이미지 빌드, catalog 노출, 무인 실행 계약, 그리고 대표 기능 경로를
보장한다. 182개 도구의 모든 옵션과 지원 파일 형식을 실제 CTF 샘플로 전수
검증했다는 뜻은 아니다. GPU는 호스트 NVIDIA 런타임, KVM 가속은 `/dev/kvm`,
디버깅은 ptrace 권한, 네트워크 도구는 대상 연결과 필요한 capability가 별도로
있어야 한다. 이 외부 조건이 없을 때도 이미지 자체의 catalog와 무인 실행
계약은 위 감사 결과대로 유지된다.
