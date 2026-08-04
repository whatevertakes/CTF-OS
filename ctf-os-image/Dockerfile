# syntax=docker/dockerfile:1.7
#
# CTF-OS 통합 이미지 — 에이전트 전용 / 국내 CTF 대상 / 단일 이미지
#
# 빌드:
#   DOCKER_BUILDKIT=1 docker build -t ctf-os:core .
#   docker build --target tools -t ctf-os:tools .   # 자산 제외, 조기 사용용
#
# 실행 (GPU 없음):
#   docker run --rm -it --cap-add SYS_PTRACE --security-opt seccomp=unconfined \
#     --shm-size=1g -v "$PWD/chal:/challenge:ro" ctf-os:core /bin/bash
#
# 에이전트용 백그라운드 실행 (기본 CMD가 PID 1 reaper로 대기):
#   docker run -d --name ctf-work -v "$PWD/chal:/challenge:ro" ctf-os:core
#
# 실행 (GPU 있음): 위에 --gpus all --device /dev/kvm 추가
#
# ─────────────────────────────────────────────────────────────────────────────
# ★ 버전과 다운로드 자산 검증 결과는 VERSIONS.md 참조
#   - pyhwp 가 Python 3.12 에서 동작하는지는 빌드 후 확인
# ─────────────────────────────────────────────────────────────────────────────


############################################################
# STAGE 1: base — 공통 런타임, 언어, uv, sage
#   가장 느리고 가장 안 변하는 것을 앞에 둔다.
############################################################
FROM ubuntu:24.04 AS base

ENV DEBIAN_FRONTEND=noninteractive \
    TERM=dumb \
    PAGER=cat \
    GIT_PAGER=cat \
    MANPAGER=cat \
    LESS=-FRX \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    LANG=C.UTF-8 \
    NVIDIA_VISIBLE_DEVICES=all \
    NVIDIA_DRIVER_CAPABILITIES=compute,utility

RUN mkdir -p /tools && : > /tools/failed.txt

# ── 공통 시스템 패키지 ────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl wget git gnupg2 unzip zip p7zip-full unrar-free \
      xz-utils zstd lz4 cabextract bzip2 \
      file bsdmainutils binutils xxd jq ripgrep fd-find tree less \
      netcat-openbsd socat nmap masscan openssl httpie \
      build-essential clang llvm cmake ninja-build meson pkg-config autoconf automake libtool \
      python3 python3-dev python3-venv \
      ruby ruby-dev \
      golang-go \
      nodejs npm \
      php-cli \
      openjdk-21-jdk-headless \
      dotnet-sdk-8.0 \
      perl \
      libssl-dev zlib1g-dev libffi-dev libgmp-dev libmpfr-dev libmpc-dev \
      libfplll-dev libeigen3-dev libz3-dev libbz2-dev libhwloc-dev \
      libpcap-dev libmhash-dev libmcrypt-dev libjpeg-dev libpng-dev \
      podman buildah skopeo fuse-overlayfs slirp4netns uidmap \
 && rm -rf /var/lib/apt/lists/*

# fd-find 는 바이너리명이 fdfind — 에이전트가 fd 로 부를 것에 대비
RUN ln -sf "$(command -v fdfind)" /usr/local/bin/fd

# ── uv / rustup ──────────────────────────────────────────────────────────
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.cargo/bin:/root/.local/bin:${PATH}"
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --profile minimal --default-toolchain stable \
 && rustc --version \
 && cargo --version

# ── main venv: 에이전트 기본 인터프리터 ──────────────────────────────────
#   충돌 없는 상용 라이브러리만. 무거운 도구는 전부 격리 venv 로 간다.
RUN uv venv /opt/venvs/main \
 && VIRTUAL_ENV=/opt/venvs/main uv pip install \
      pwntools requests httpx \
      pycryptodome cryptography gmpy2 sympy galois ecdsa tinyec fpylll \
      z3-solver PyJWT \
      numpy scipy pandas networkx ortools python-constraint \
      Pillow opencv-python-headless scikit-image \
      pytesseract chardet olefile scapy \
      flask fastapi uvicorn \
      tqdm pyyaml
ENV PATH="/opt/venvs/main/bin:${PATH}"

# ── SageMath (24.04 아카이브에 없음 → conda-forge) ───────────────────────
#   ★ python 버전 핀을 걸지 말 것. solve 가 깨진다.
ENV MAMBA_ROOT_PREFIX=/opt/mamba
RUN curl -Ls https://micro.mamba.pm/api/micromamba/linux-64/latest \
      | tar -xj -C /usr/local bin/micromamba \
 && micromamba create -y -n sage -c conda-forge sage \
 && micromamba clean -a -y
RUN printf '#!/bin/sh\nexec /opt/mamba/envs/sage/bin/sage "$@"\n' > /usr/local/bin/sage \
 && chmod +x /usr/local/bin/sage \
 && sage --version

# 기존 venv를 유지하면서 실제로 깨졌거나 빠진 런타임 의존성만 보강한다.
RUN VIRTUAL_ENV=/opt/venvs/main uv pip install \
      "cysignals==1.12.6" \
      "beautifulsoup4==4.15.0" "lxml==6.1.1" "h2==4.4.0" \
      "websockets==16.1.1" "brotlipy==0.7.0" \
 && VIRTUAL_ENV=/opt/venvs/main uv pip install \
      "h2spacex==1.2.2" --no-deps \
 && /opt/venvs/main/bin/python -c \
      'import bs4, cysignals, fpylll, h2, h2spacex, lxml, websockets'
RUN uv pip install --python /opt/mamba/envs/sage/bin/python \
      "pycryptodome==3.23.0" \
 && /opt/mamba/envs/sage/bin/python -c 'from Crypto.Util.number import long_to_bytes' \
 && printf '%s\n' \
      '#!/usr/bin/env bash' \
      'set -euo pipefail' \
      'if (($# == 0)); then' \
      '  printf "Usage: sage-python SCRIPT.py [ARGS...] | sage-python -c CODE\\n" >&2' \
      '  exit 2' \
      'fi' \
      'exec /opt/mamba/envs/sage/bin/python "$@"' \
      > /usr/local/bin/sage-python \
 && chmod +x /usr/local/bin/sage-python


############################################################
# STAGE 2: assets — 대용량 오프라인 자산
#   도구 스테이지와 독립. 도구를 바꿔도 여기가 재다운로드되지 않는다.
#   BuildKit 이 tools 스테이지와 병렬로 처리한다.
############################################################
FROM ubuntu:24.04 AS assets
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl wget git unzip xz-utils bzip2 zstd \
      binutils file perl \
 && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /assets

# ── 워드리스트 (SecLists 부분 체크아웃 + rockyou) ─────────────────────────
ARG SECLISTS_REF=aeb36e9df937d1b77042e5667780e8156cd419f7
RUN git init /assets/wordlists/SecLists \
 && git -C /assets/wordlists/SecLists remote add origin \
      https://github.com/danielmiessler/SecLists \
 && git -C /assets/wordlists/SecLists sparse-checkout init --cone \
 && git -C /assets/wordlists/SecLists sparse-checkout set \
      Discovery/Web-Content \
      Passwords/Common-Credentials \
      Passwords/Leaked-Databases \
      Fuzzing/special-chars \
      Usernames \
 && git -C /assets/wordlists/SecLists fetch --depth=1 origin \
      "${SECLISTS_REF}" \
 && git -C /assets/wordlists/SecLists checkout --detach FETCH_HEAD \
 && test -f \
      /assets/wordlists/SecLists/Passwords/Leaked-Databases/rockyou.txt.tar.gz \
 && tar -xzf \
      /assets/wordlists/SecLists/Passwords/Leaked-Databases/rockyou.txt.tar.gz \
      -C /assets/wordlists \
 && rm -rf /assets/wordlists/SecLists/.git

# ── libc-database ────────────────────────────────────────────────────────
#   ./get 은 여러 카테고리를 받는다. 전체 출력은 파일에 보관하고 크기만 출력한다.
ARG LIBC_DATABASE_REF=291b0ebf126de9961cd2f8dd1cea2654c57a594a
RUN git init /assets/libc-database \
 && git -C /assets/libc-database remote add origin \
      https://github.com/niklasb/libc-database \
 && git -C /assets/libc-database fetch --depth=1 origin \
      "${LIBC_DATABASE_REF}" \
 && git -C /assets/libc-database checkout --detach FETCH_HEAD \
 && cd /assets/libc-database \
 && if ! ./get ubuntu debian > /tmp/libc-database-get.log 2>&1; then \
      tail -n 100 /tmp/libc-database-get.log; exit 1; \
    fi \
 && du -sh /assets/libc-database \
 && rm /tmp/libc-database-get.log \
 && rm -rf /assets/libc-database/.git

# ── Volatility 심볼 ──────────────────────────────────────────────────────
# windows.zip은 약 800 MiB라 일시적인 CDN reset이 발생할 수 있다. 실패한
# 레이어에서도 부분 파일을 BuildKit cache에 남기고 다음 시도에서 Range 재개한다.
ARG VOLATILITY_WINDOWS_SYMBOLS_SHA256=231d69735b9a5482b16bdbf1ec356e0a95574c44079e68dfb02ebddb34d55f3e
ARG VOLATILITY_LINUX_SYMBOLS_SHA256=58bb7da2ed1e491ce922d04a59881d201e233b5605c9fd5a7f0c08ee528253c6
ARG VOLATILITY_MAC_SYMBOLS_SHA256=fd12c8338724b175b0c5765af3313328b700ad53de4a00b4aa50e9a8bcef9129
RUN --mount=type=cache,id=ctf-volatility-symbols,target=/var/cache/ctf-volatility,sharing=locked \
    set -eu; \
    mkdir -p /assets/volatility3/symbols; \
    for s in windows linux mac; do \
      archive="/var/cache/ctf-volatility/${s}.zip"; \
      partial="${archive}.part"; \
      case "${s}" in \
        windows) expected="${VOLATILITY_WINDOWS_SYMBOLS_SHA256}" ;; \
        linux) expected="${VOLATILITY_LINUX_SYMBOLS_SHA256}" ;; \
        mac) expected="${VOLATILITY_MAC_SYMBOLS_SHA256}" ;; \
      esac; \
      if ! unzip -tq "${archive}" >/dev/null 2>&1 \
          || ! echo "${expected}  ${archive}" | sha256sum -c - >/dev/null 2>&1; then \
        rm -f -- "${archive}"; \
        if unzip -tq "${partial}" >/dev/null 2>&1 \
            && echo "${expected}  ${partial}" | sha256sum -c - >/dev/null 2>&1; then \
          mv -f -- "${partial}" "${archive}"; \
        else \
          rm -f -- "${partial}"; \
          attempt=0; \
          while [ "${attempt}" -lt 10 ]; do \
            attempt=$((attempt + 1)); \
            if curl -fsSL --show-error --connect-timeout 30 --max-time 1800 \
                --speed-limit 1024 --speed-time 30 \
                --retry 5 --retry-all-errors --retry-delay 3 \
                -C - -o "${partial}" \
                "https://downloads.volatilityfoundation.org/volatility3/symbols/${s}.zip"; then \
              if unzip -tq "${partial}" >/dev/null 2>&1 \
                  && echo "${expected}  ${partial}" | sha256sum -c - >/dev/null 2>&1; then \
                mv -f -- "${partial}" "${archive}"; \
                break; \
              fi; \
              rm -f -- "${partial}"; \
            fi; \
            sleep 3; \
          done; \
        fi; \
      fi; \
      unzip -tq "${archive}" >/dev/null; \
      echo "${expected}  ${archive}" | sha256sum -c -; \
      install -m 0644 "${archive}" "/assets/volatility3/symbols/${s}.zip"; \
    done; \
    printf '%s  %s\n' \
      "${VOLATILITY_WINDOWS_SYMBOLS_SHA256}" windows.zip \
      "${VOLATILITY_LINUX_SYMBOLS_SHA256}" linux.zip \
      "${VOLATILITY_MAC_SYMBOLS_SHA256}" mac.zip \
      > /assets/volatility3/symbols/SHA256SUMS

# pyhwp의 실제 HWP5 parser smoke에 사용하는 upstream 고정 fixture.
ARG PYHWP_FIXTURE_REF=83239f0d3bdf438b2c9f7dcff455a6e841154a39
ARG PYHWP_FIXTURE_SHA256=8eb333ab110db6f91d7e426d507d41ca09cacd4d40d945188b5ec40663d7576b
RUN mkdir -p /assets/ctf-capability-fixtures \
 && curl -fsSL --retry 5 --retry-all-errors \
      -o /assets/ctf-capability-fixtures/charshape.hwp \
      "https://raw.githubusercontent.com/mete0r/pyhwp/${PYHWP_FIXTURE_REF}/tests/hwp5_tests/fixtures/charshape.hwp" \
 && echo "${PYHWP_FIXTURE_SHA256}  /assets/ctf-capability-fixtures/charshape.hwp" \
      | sha256sum -c -

# ── nuclei 템플릿 (커밋 고정) ────────────────────────────────────────────
ARG NUCLEI_TEMPLATES_REF=4ccef9ea7c907d917b1608d60d73b12823bdfdf5
RUN git init /assets/nuclei-templates \
 && git -C /assets/nuclei-templates remote add origin \
      https://github.com/projectdiscovery/nuclei-templates \
 && git -C /assets/nuclei-templates fetch --depth=1 origin "${NUCLEI_TEMPLATES_REF}" \
 && git -C /assets/nuclei-templates checkout --detach FETCH_HEAD \
 && rm -rf /assets/nuclei-templates/.git

# SecLists에는 rockyou-withcount와 일반 rockyou 아카이브가 함께 있다.
# 풀이 도구가 기대하는 한 줄당 암호 형식은 일반 rockyou.txt이다.
RUN tar -xzf \
      /assets/wordlists/SecLists/Passwords/Leaked-Databases/rockyou.txt.tar.gz \
      -C /assets/wordlists rockyou.txt \
 && test -s /assets/wordlists/rockyou.txt \
 && rm -f /assets/wordlists/rockyou-withcount.txt


############################################################
# STAGE 3: tools — 카테고리별 도구
#   여기까지가 조기 사용 가능한 산출물 (--target tools)
############################################################
FROM base AS tools

# ─────────────────────────────────────────────────────────────────────────
# PWN
# ─────────────────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
      gdb gdb-multiarch gdbserver checksec patchelf elfutils \
      strace ltrace valgrind dwarves \
      gcc-13-multilib libc6-dev-i386 \
      qemu-user-static qemu-system-x86 qemu-system-arm qemu-system-mips \
      busybox-static cpio \
      gcc-aarch64-linux-gnu gcc-arm-linux-gnueabihf \
      gcc-mips-linux-gnu gcc-mipsel-linux-gnu gcc-riscv64-linux-gnu \
      libc6-dev-arm64-cross libc6-dev-armhf-cross \
 && rm -rf /var/lib/apt/lists/*

RUN gem install --no-document one_gadget --version 1.10.0 \
 && gem install --no-document seccomp-tools --version 1.6.2 \
 && gem install --no-document zsteg --version 0.2.14

# pwndbg
ARG PWNDBG_VER=2026.02.18
RUN curl -fsSL -o /tmp/pwndbg.deb \
      "https://github.com/pwndbg/pwndbg/releases/download/${PWNDBG_VER}/pwndbg_${PWNDBG_VER}_amd64.deb" \
 && dpkg -i /tmp/pwndbg.deb \
 && rm /tmp/pwndbg.deb

# ★ 순서 중요: pwndbg 를 source 한 뒤에 배치 설정을 덮어써야 페이저에서 안 멈춘다
RUN set -eux; \
    PWNDBG_GDBINIT="$(find /usr -type f -path '*/pwndbginit/gdbinit.py' -print -quit)"; \
    test -n "${PWNDBG_GDBINIT}"; \
    printf 'source %s\nset pagination off\nset confirm off\nset height 0\nset width 0\n' \
      "${PWNDBG_GDBINIT}" > /root/.gdbinit; \
    if ! /usr/bin/gdb -batch -ex 'vmmap' > /tmp/pwndbg-system-gdb.log 2>&1 || \
        grep -q 'Undefined command.*vmmap' /tmp/pwndbg-system-gdb.log; then \
      PWNDBG_ENTRY="$(find /usr/lib -type f -path '*/pwndbg-gdb/bin/pwndbg' \
        -perm /u+x -print -quit)"; \
      test -n "${PWNDBG_ENTRY}"; \
      ln -sf "${PWNDBG_ENTRY}" /usr/local/bin/gdb; \
      printf 'pwndbg: using bundled gdb entrypoint %s\n' "${PWNDBG_ENTRY}"; \
    else \
      printf 'pwndbg: loaded by system gdb\n'; \
    fi; \
    if ! gdb -batch -ex 'vmmap' > /tmp/pwndbg-gdb.log 2>&1; then \
      cat /tmp/pwndbg-system-gdb.log /tmp/pwndbg-gdb.log; \
      exit 1; \
    fi; \
    ! grep -q 'Undefined command.*vmmap' /tmp/pwndbg-gdb.log; \
    rm /tmp/pwndbg-system-gdb.log /tmp/pwndbg-gdb.log

# pwninit — libc 매칭·패치·스켈레톤 생성
ARG PWNINIT_VER=3.3.1
RUN curl -fsSL -o /usr/local/bin/pwninit \
      "https://github.com/io12/pwninit/releases/download/${PWNINIT_VER}/pwninit" \
 && chmod +x /usr/local/bin/pwninit

# 커널 pwn
ARG VMLINUX_TO_ELF_REF=19683fb95b29cd31362d49e6f48ab8368f96cbdf
ARG EXTRACT_VMLINUX_REF=8ba098e6b6ff0db8edf28528d1552be261af30d4
ARG EXTRACT_VMLINUX_SHA256=aacb6bb09af227a6cf508f5283458f001722a39abd9c4cfb026bc97c31624910
RUN uv venv /opt/venvs/kernel \
 && VIRTUAL_ENV=/opt/venvs/kernel uv pip install \
      "git+https://github.com/marin-m/vmlinux-to-elf@${VMLINUX_TO_ELF_REF}" \
 && ln -sf /opt/venvs/kernel/bin/vmlinux-to-elf /usr/local/bin/vmlinux-to-elf \
 && curl -fsSL -o /usr/local/bin/extract-vmlinux \
      "https://raw.githubusercontent.com/torvalds/linux/${EXTRACT_VMLINUX_REF}/scripts/extract-vmlinux" \
 && echo "${EXTRACT_VMLINUX_SHA256}  /usr/local/bin/extract-vmlinux" \
      | sha256sum -c - \
 && chmod +x /usr/local/bin/extract-vmlinux

# angr / ROP 도구 (격리)
RUN uv venv /opt/venvs/angr \
 && VIRTUAL_ENV=/opt/venvs/angr uv pip install angr capstone unicorn keystone-engine \
 && ln -sf /opt/venvs/angr/bin/python /usr/local/bin/angr-python
RUN VIRTUAL_ENV=/opt/venvs/main uv pip install ROPgadget ropper

# ropr — vmlinux 같은 대형 바이너리에서도 빠른 ROP gadget 검색
ARG ROPR_REF=cf2e2d384e67328cd9d27537172927ed9a27e5ab
RUN cargo install --locked \
      --git https://github.com/Ben-Lichtman/ropr \
      --rev "${ROPR_REF}" --root /usr/local ropr \
 && ropr --version | grep -F 'ropr 0.2.27'

ENV PWNLIB_NOTERM=1 PWNLIB_SILENT=1

# ─────────────────────────────────────────────────────────────────────────
# REV
# ─────────────────────────────────────────────────────────────────────────
RUN dpkg --add-architecture i386 \
 && apt-get update && apt-get install -y --no-install-recommends \
      radare2 upx-ucl yara binwalk wabt binaryen \
      wine wine64 wine32:i386 mono-runtime \
 && rm -rf /var/lib/apt/lists/*

# Ubuntu의 wine64 실행 파일은 PATH 밖에 있다. 32/64비트 Wine 패키지는
# 모두 유지하되, 인자 없는 prefix 초기화나 GUI 진입은 막는다.
RUN printf '%s\n' \
      '#!/usr/bin/env bash' \
      'set -euo pipefail' \
      'if (($# == 0)); then' \
      '  printf "Usage: %s PROGRAM.exe [ARGS...] | %s --version\\n" "${0##*/}" "${0##*/}" >&2' \
      '  exit 2' \
      'fi' \
      'export WINEDEBUG="${WINEDEBUG:--all}"' \
      'if [[ "${0##*/}" == wine64 ]]; then' \
      '  exec /usr/lib/wine/wine64 "$@"' \
      'fi' \
      'exec /usr/bin/wine "$@"' \
      > /usr/local/bin/wine \
 && ln -sf wine /usr/local/bin/wine64 \
 && chmod 0755 /usr/local/bin/wine \
 && test -x /usr/bin/wine -a -x /usr/lib/wine/wine64 \
 && wine --version | grep -F 'wine-9.0' \
 && wine64 --version | grep -F 'wine-9.0'

# Ghidra
ARG GHIDRA_VER=12.1.2
ARG GHIDRA_DATE=20260605
RUN curl -fsSL -o /tmp/ghidra.zip \
      "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VER}_build/ghidra_${GHIDRA_VER}_PUBLIC_${GHIDRA_DATE}.zip" \
 && unzip -q /tmp/ghidra.zip -d /opt \
 && mv /opt/ghidra_* /opt/ghidra \
 && rm /tmp/ghidra.zip \
 && test "$(sed -n 's/^application.java.min=//p' /opt/ghidra/Ghidra/application.properties)" = 21
ENV GHIDRA_INSTALL_DIR=/opt/ghidra
RUN uv venv /opt/venvs/ghidra \
 && VIRTUAL_ENV=/opt/venvs/ghidra uv pip install --no-index \
      --find-links /opt/ghidra/Ghidra/Features/PyGhidra/pypkg/dist pyghidra

# Java / Android
ARG JADX_VER=1.5.6
ARG APKTOOL_VER=3.0.3
ARG CFR_VER=0.152
RUN mkdir -p /opt/ctf-tools/java && cd /opt/ctf-tools/java \
 && curl -fsSLO "https://github.com/skylot/jadx/releases/download/v${JADX_VER}/jadx-${JADX_VER}.zip" \
 && unzip -q "jadx-${JADX_VER}.zip" -d jadx && rm "jadx-${JADX_VER}.zip" \
 && ln -sf /opt/ctf-tools/java/jadx/bin/jadx /usr/local/bin/jadx \
 && ln -sf /opt/ctf-tools/java/jadx/bin/jadx-gui /usr/local/bin/jadx-cli \
 && curl -fsSL -o apktool.jar \
      "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VER}/apktool_${APKTOOL_VER}.jar" \
 && printf '#!/bin/sh\nexec java -jar /opt/ctf-tools/java/apktool.jar "$@"\n' > /usr/local/bin/apktool \
 && curl -fsSL -o cfr.jar \
      "https://github.com/leibnitz27/cfr/releases/download/${CFR_VER}/cfr-${CFR_VER}.jar" \
 && printf '#!/bin/sh\nexec java -jar /opt/ctf-tools/java/cfr.jar "$@"\n' > /usr/local/bin/cfr \
 && chmod +x /usr/local/bin/apktool /usr/local/bin/cfr \
 && test "$(java -jar /opt/ctf-tools/java/apktool.jar --version)" = "${APKTOOL_VER}"

# .NET (dotnet-sdk-8.0 은 base 에서 apt 로 설치됨)
# ILSpy 10.x 는 .NET 10 전용이므로 .NET 8 호환 최신 릴리스인 9.1을 사용한다.
ARG ILSPYCMD_VER=9.1.0.7988
RUN dotnet tool install --global ilspycmd --version "${ILSPYCMD_VER}" \
 && /root/.dotnet/tools/ilspycmd --version | grep -F "${ILSPYCMD_VER}"
ENV PATH="/root/.dotnet/tools:${PATH}"
RUN VIRTUAL_ENV=/opt/venvs/main uv pip install dnfile pefile

# Python 바이트코드
ARG PYCDC_REF=b4289760970dbc399684f1e155ec6d1ea1cc787e
RUN git init /tmp/pycdc \
 && git -C /tmp/pycdc remote add origin https://github.com/zrax/pycdc \
 && git -C /tmp/pycdc fetch --depth=1 origin "${PYCDC_REF}" \
 && git -C /tmp/pycdc checkout --detach FETCH_HEAD \
 && cmake -S /tmp/pycdc -B /tmp/pycdc/build -DCMAKE_BUILD_TYPE=Release \
 && cmake --build /tmp/pycdc/build -j"$(nproc)" \
 && install -m755 /tmp/pycdc/build/pycdc /tmp/pycdc/build/pycdas /usr/local/bin/ \
 && rm -rf /tmp/pycdc
RUN uv venv /opt/venvs/pydec \
 && VIRTUAL_ENV=/opt/venvs/pydec uv pip install uncompyle6 xdis \
 && ln -sf /opt/venvs/pydec/bin/uncompyle6 /usr/local/bin/uncompyle6 \
 && ln -sf /opt/venvs/pydec/bin/pydisasm /usr/local/bin/pydisasm
ARG PYINSTXTRACTOR_REF=815d31cf26bc71e62f851b2e549452e7b7c9dd98
ARG PYINSTXTRACTOR_SHA256=94e0b6c9d5151bbeefc7e7452e96e24b396c2dbfcb0348e5f12c4c0865fefe58
RUN curl -fsSL -o /usr/local/bin/pyinstxtractor.py \
      "https://raw.githubusercontent.com/extremecoders-re/pyinstxtractor/${PYINSTXTRACTOR_REF}/pyinstxtractor.py" \
 && echo "${PYINSTXTRACTOR_SHA256}  /usr/local/bin/pyinstxtractor.py" \
      | sha256sum -c -

# Go / Rust 심볼
ARG GORESYM_VER=3.4
RUN curl -fsSL -o /tmp/goresym.zip \
      "https://github.com/mandiant/GoReSym/releases/download/v${GORESYM_VER}/GoReSym-linux.zip" \
 && unzip -q /tmp/goresym.zip -d /usr/local/bin GoReSym \
 && chmod +x /usr/local/bin/GoReSym \
 && rm /tmp/goresym.zip
RUN cargo install --locked --root /usr/local rustfilt

# Frida (격리)
RUN uv venv /opt/venvs/frida \
 && VIRTUAL_ENV=/opt/venvs/frida uv pip install frida-tools objection \
 && for b in frida frida-ps frida-trace frida-discover objection; do \
      ln -sf "/opt/venvs/frida/bin/$b" "/usr/local/bin/$b"; done

# capa / FLOSS
RUN uv venv /opt/venvs/flare \
 && VIRTUAL_ENV=/opt/venvs/flare uv pip install flare-capa flare-floss \
 && ln -sf /opt/venvs/flare/bin/capa /usr/local/bin/capa \
 && ln -sf /opt/venvs/flare/bin/floss /usr/local/bin/floss

# ─────────────────────────────────────────────────────────────────────────
# CRYPTO
# ─────────────────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
      pari-gp gmp-ecm gnupg age hashcat ocl-icd-libopencl1 ocl-icd-opencl-dev \
      yasm libomp-dev libopenblas-dev msolve libm4ri-dev \
 && rm -rf /var/lib/apt/lists/*

# PySAT publishes the original solver implementations with its wheel.  Exercise
# both a satisfiable and an unsatisfiable instance for the exact CaDiCaL and
# Kissat backends that the capability contract exposes.
ARG PYTHON_SAT_VER=1.9.dev7
RUN VIRTUAL_ENV=/opt/venvs/main uv pip install \
      "python-sat==${PYTHON_SAT_VER}" \
 && /opt/venvs/main/bin/python -c \
      'import importlib.metadata as m; assert m.version("python-sat") == "1.9.dev7"' \
 && /opt/venvs/main/bin/python -c \
      'from pysat.solvers import Solver; s=Solver(name="cadical300", bootstrap_with=[[1],[-1,2]]); assert s.solve() and s.get_model(); s.delete(); s=Solver(name="cadical300", bootstrap_with=[[1],[-1]]); assert not s.solve(); s.delete()' \
 && /opt/venvs/main/bin/python -c \
      'from pysat.solvers import Solver; s=Solver(name="kissat404", bootstrap_with=[[1],[-1,2]]); assert s.solve() and s.get_model(); s.delete(); s=Solver(name="kissat404", bootstrap_with=[[1],[-1]]); assert not s.solve(); s.delete()'

# CryptoMiniSat official release binary.  The GitHub release API reports this
# checksum for the static Linux amd64 asset; verify it before installation and
# solve a real DIMACS instance instead of treating --version as readiness.
ARG CRYPTOMINISAT_VER=5.14.7
ARG CRYPTOMINISAT_SHA256=536d4cb03bbd2b4cbcca6230ed30e2aa844f170b5bbcfb0a0d7adb4852cf3ab7
RUN set -eux; \
    archive=/tmp/cryptominisat.tar.gz; \
    curl -fsSL --retry 3 -o "${archive}" \
      "https://github.com/msoos/cryptominisat/releases/download/release/v${CRYPTOMINISAT_VER}/cryptominisat5-v${CRYPTOMINISAT_VER}-linux-amd64.tar.gz"; \
    echo "${CRYPTOMINISAT_SHA256}  ${archive}" | sha256sum -c -; \
    tar -xzf "${archive}" -C /usr/local/bin cryptominisat5; \
    chmod 0755 /usr/local/bin/cryptominisat5; \
    cryptominisat5 --version | grep -F \
      "CryptoMiniSat version ${CRYPTOMINISAT_VER}"; \
    if printf 'p cnf 2 2\n1 0\n-1 2 0\n' \
        | cryptominisat5 --verb 0 >/tmp/cryptominisat-smoke.log; then \
      solver_status=0; \
    else \
      solver_status=$?; \
    fi; \
    test "${solver_status}" -eq 10; \
    grep -Fx 's SATISFIABLE' /tmp/cryptominisat-smoke.log; \
    rm -f "${archive}" /tmp/cryptominisat-smoke.log

# flatter — 대형 격자 축약
ARG FLATTER_REF=d2b8026f29b4a69e987b15d4b240f8a5053275d3
RUN git init /tmp/flatter \
 && git -C /tmp/flatter remote add origin https://github.com/keeganryan/flatter \
 && git -C /tmp/flatter fetch --depth=1 origin "${FLATTER_REF}" \
 && git -C /tmp/flatter checkout --detach FETCH_HEAD \
 && cmake -S /tmp/flatter -B /tmp/flatter/build -DCMAKE_BUILD_TYPE=Release \
 && cmake --build /tmp/flatter/build -j"$(nproc)" \
 && cmake --install /tmp/flatter/build && ldconfig && rm -rf /tmp/flatter \
 && flatter -h >/dev/null

# RsaCtfTool (격리 — 의존성 핀이 넓다)
ARG RSACTFTOOL_REF=7c98848f1945de3e67a420871e8672f5ad9aa5d5
RUN git init /opt/ctf-tools/RsaCtfTool \
 && git -C /opt/ctf-tools/RsaCtfTool remote add origin \
      https://github.com/RsaCtfTool/RsaCtfTool \
 && git -C /opt/ctf-tools/RsaCtfTool fetch --depth=1 origin \
      "${RSACTFTOOL_REF}" \
 && git -C /opt/ctf-tools/RsaCtfTool checkout --detach FETCH_HEAD \
 && uv venv /opt/venvs/rsactftool \
 && VIRTUAL_ENV=/opt/venvs/rsactftool uv pip install /opt/ctf-tools/RsaCtfTool \
 && printf '#!/bin/sh\nexec /opt/venvs/rsactftool/bin/python /opt/ctf-tools/RsaCtfTool/RsaCtfTool.py "$@"\n' \
      > /usr/local/bin/RsaCtfTool && chmod +x /usr/local/bin/RsaCtfTool

# CADO-NFS
ARG CADO_NFS_REF=d67f463a8e5d2f4ab79cd114441b2cf982dc0da7
RUN git init /opt/cado-nfs \
 && git -C /opt/cado-nfs remote add origin \
      https://gitlab.inria.fr/cado-nfs/cado-nfs.git \
 && git -C /opt/cado-nfs fetch --depth=1 origin "${CADO_NFS_REF}" \
 && git -C /opt/cado-nfs checkout --detach FETCH_HEAD \
 && cd /opt/cado-nfs && make -j"$(nproc)"

# ★ CADO-NFS 는 빌드 디렉터리를 호스트명으로 찾는다.
#   컨테이너는 실행마다 호스트명이 랜덤 → 래퍼 없으면 실행이 전부 실패한다.
RUN printf '#!/bin/bash\n\
B=/opt/cado-nfs/build\n\
H=$(hostname)\n\
if [ ! -d "$B/$H" ]; then\n\
  S=$(ls -d "$B"/* 2>/dev/null | head -1)\n\
  [ -n "$S" ] && ln -sf "$S" "$B/$H"\n\
fi\n\
exec python3 /opt/cado-nfs/cado-nfs.py "$@"\n' > /usr/local/bin/cado-nfs \
 && chmod +x /usr/local/bin/cado-nfs

# John the Ripper jumbo (소스)
ARG JOHN_REF=94caf43756b1f13c7e3829ff848df344ea755cac
RUN git init /opt/john \
 && git -C /opt/john remote add origin https://github.com/openwall/john \
 && git -C /opt/john fetch --depth=1 origin "${JOHN_REF}" \
 && git -C /opt/john checkout --detach FETCH_HEAD \
 && cd /opt/john/src && ./configure && make -sj"$(nproc)"
RUN printf '#!/bin/sh\nexec /opt/john/run/john "$@"\n' > /usr/local/bin/john \
 && chmod +x /usr/local/bin/john \
 && /usr/local/bin/john --list=build-info >/dev/null
ENV PATH="/usr/local/bin:/opt/john/run:${PATH}"

RUN VIRTUAL_ENV=/opt/venvs/main uv pip install xortool hashid name-that-hash factordb-pycli

# cuso — Sage 기반 다변수 Coppersmith 자동화
ARG CUSO_REF=fb2747d2105a8e48499bf10a3a717cf80c14d079
RUN git init /tmp/cuso \
 && git -C /tmp/cuso remote add origin https://github.com/keeganryan/cuso \
 && git -C /tmp/cuso fetch --depth=1 origin "${CUSO_REF}" \
 && git -C /tmp/cuso checkout --detach FETCH_HEAD \
 && uv pip install --python /opt/mamba/envs/sage/bin/python /tmp/cuso \
 && /opt/mamba/envs/sage/bin/python -c 'import cuso' \
 && rm -rf /tmp/cuso

# gf2bv — GF(2) 비트벡터 선형/비선형 모델링
ARG GF2BV_REF=4357db5cae0dc1213526b93180b9a26f14a91070
RUN git init /tmp/gf2bv \
 && git -C /tmp/gf2bv remote add origin https://github.com/maple3142/gf2bv \
 && git -C /tmp/gf2bv fetch --depth=1 origin "${GF2BV_REF}" \
 && git -C /tmp/gf2bv checkout --detach FETCH_HEAD \
 && VIRTUAL_ENV=/opt/venvs/main uv pip install /tmp/gf2bv \
 && /opt/venvs/main/bin/python -c 'import gf2bv' \
 && rm -rf /tmp/gf2bv

# hash_extender — Merkle-Damgård 해시 길이 확장
ARG HASH_EXTENDER_REF=f00b1a02eca02b0907e26726f7efe437bc396aa4
RUN git init /tmp/hash-extender \
 && git -C /tmp/hash-extender remote add origin \
      https://github.com/iagox86/hash_extender \
 && git -C /tmp/hash-extender fetch --depth=1 origin "${HASH_EXTENDER_REF}" \
 && git -C /tmp/hash-extender checkout --detach FETCH_HEAD \
 && make -C /tmp/hash-extender -j"$(nproc)" \
 && /tmp/hash-extender/hash_extender \
      --data data --secret 6 --append append \
      --signature 6036708eba0d11f6ef52ad44e8b74d5b --format md5 \
      | grep -F 'New signature: 6ee582a1669ce442f3719c47430dadee' \
 && install -m 0755 /tmp/hash-extender/hash_extender \
      /usr/local/bin/hash_extender \
 && rm -rf /tmp/hash-extender

# 격리된 Python 기능을 매니페스트에서 찾을 수 있는 무인 진입점으로 노출한다.
RUN printf '%s\n' \
      '#!/usr/bin/env bash' \
      'set -euo pipefail' \
      'if (($# == 0)); then' \
      '  printf "Usage: crypto-python SCRIPT.py [ARGS...] | crypto-python -c CODE\\n" >&2' \
      '  exit 2' \
      'fi' \
      'exec /opt/venvs/main/bin/python "$@"' \
      > /usr/local/bin/crypto-python \
 && chmod 0755 /usr/local/bin/crypto-python

# ─────────────────────────────────────────────────────────────────────────
# FORENSIC
# ─────────────────────────────────────────────────────────────────────────
ARG TESSERACT_VER=5.3.4-1build5
ARG TESSERACT_LANG_VER=1:4.1.0-2
RUN apt-get update && apt-get install -y --no-install-recommends \
      sleuthkit testdisk foremost scalpel \
      tshark tcpdump ngrep \
      libimage-exiftool-perl \
      ntfs-3g xfsprogs btrfs-progs dcfldd \
      libregf-utils libevtx-utils qemu-utils squashfs-tools \
      poppler-utils qpdf \
      ssdeep clamav clamav-freshclam \
      "tesseract-ocr=${TESSERACT_VER}" \
      "tesseract-ocr-eng=${TESSERACT_LANG_VER}" \
      "tesseract-ocr-kor=${TESSERACT_LANG_VER}" \
      "tesseract-ocr-kor-vert=${TESSERACT_LANG_VER}" \
      fonts-nanum fonts-nanum-coding \
      libreoffice-writer libreoffice-calc libreoffice-impress \
      flex libabsl-dev libre2-dev libxml2-utils libewf-dev ewf-tools \
 && rm -rf /var/lib/apt/lists/*

# bulk_extractor 는 Ubuntu 24.04 패키지가 없어 공식 안정 릴리스를 소스 빌드한다.
ARG BULK_EXTRACTOR_VER=2.1.1
RUN git clone --depth=1 --branch "v${BULK_EXTRACTOR_VER}" \
      --recurse-submodules --shallow-submodules \
      https://github.com/simsong/bulk_extractor.git /tmp/bulk-extractor \
 && cd /tmp/bulk-extractor \
 && ./bootstrap.sh \
 && ./configure --enable-silent-rules \
 && make -j"$(nproc)" \
 && make install \
 && rm -rf /tmp/bulk-extractor \
 && bulk_extractor -V | grep -F "${BULK_EXTRACTOR_VER}"

# ★ ClamAV: 시그니처 DB 를 빌드 시점에 굽는다 (오프라인 필수). 데몬은 띄우지 않는다.
RUN sed -i 's/^Example/#Example/' /etc/clamav/freshclam.conf 2>/dev/null || true \
 && freshclam

# Zeek. OBS only retains the newest package, so use the retained official
# release tarball and verify its bytes instead of pinning an evictable apt
# version.
ARG ZEEK_VER=8.2.1
ARG ZEEK_SHA256=a8067c75cc89bef4b58019230434a90073671a7cabfcf7ac616ac872a40a2edd
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bison cppzmq-dev libfl-dev libmaxminddb-dev libzmq3-dev swig \
      python3-git python3-semantic-version python3-websockets \
 && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL --retry 5 --retry-all-errors \
      -o /tmp/zeek.tar.gz \
      "https://download.zeek.org/zeek-${ZEEK_VER}.tar.gz" \
 && echo "${ZEEK_SHA256}  /tmp/zeek.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/zeek.tar.gz -C /tmp \
 && cd "/tmp/zeek-${ZEEK_VER}" \
 && ./configure --prefix=/opt/zeek --build-type=Release \
 && make -j"$(nproc)" \
 && make install \
 && /opt/zeek/bin/zeek --version > /tmp/zeek.version 2>&1 \
 && grep -F "zeek version ${ZEEK_VER}" /tmp/zeek.version \
 && rm /tmp/zeek.version \
 && rm -rf /tmp/zeek.tar.gz "/tmp/zeek-${ZEEK_VER}"
ENV PATH="/opt/zeek/bin:${PATH}"

# Volatility 3 (격리)
ARG VOLATILITY3_VER=2.28.0
RUN uv venv /opt/venvs/vol3 \
 && VIRTUAL_ENV=/opt/venvs/vol3 uv pip install \
      "volatility3==${VOLATILITY3_VER}" \
 && ln -sf /opt/venvs/vol3/bin/vol /usr/local/bin/vol
ARG DWARF2JSON_VER=0.9.0
ARG DWARF2JSON_SHA256=e2e75ba5bc9c22bc38a48edffbb050456d089d54998d54f46cb580223d9fbc6b
RUN curl -fsSL -o /usr/local/bin/dwarf2json \
      "https://github.com/volatilityfoundation/dwarf2json/releases/download/v${DWARF2JSON_VER}/dwarf2json-linux-amd64" \
 && echo "${DWARF2JSON_SHA256}  /usr/local/bin/dwarf2json" \
      | sha256sum -c - \
 && chmod +x /usr/local/bin/dwarf2json

# 문서 분석
RUN uv venv /opt/venvs/docs \
 && VIRTUAL_ENV=/opt/venvs/docs uv pip install oletools XLMMacroDeobfuscator pdfid peepdf-3 \
 && printf '#!/bin/sh\nexec /opt/venvs/docs/bin/python -m pdfid "$@"\n' \
      > /usr/local/bin/pdfid \
 && chmod +x /usr/local/bin/pdfid

# ★ 한글 문서
ARG PYHWP_VER=0.1b15
RUN uv venv /opt/venvs/hwp \
 && VIRTUAL_ENV=/opt/venvs/hwp uv pip install \
      "pyhwp==${PYHWP_VER}" "olefile==0.47" "chardet==7.4.3" "six==1.17.0" \
 && for b in hwp5txt hwp5proc hwp5odt; do \
      ln -sf "/opt/venvs/hwp/bin/$b" "/usr/local/bin/$b" 2>/dev/null || true; done \
 && /opt/venvs/hwp/bin/hwp5txt --version \
      | grep -F "hwp5txt ${PYHWP_VER}"

# ─────────────────────────────────────────────────────────────────────────
# WEB
# ─────────────────────────────────────────────────────────────────────────
# Go/Rust 릴리스 바이너리
ARG FFUF_VER=2.2.1
ARG NUCLEI_VER=3.11.0
ARG DALFOX_VER=3.1.2
ARG FEROX_VER=2.13.1
RUN set -eux; cd /tmp; \
    curl -fsSLO "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VER}/ffuf_${FFUF_VER}_linux_amd64.tar.gz" && \
      tar -xzf ffuf_*.tar.gz -C /usr/local/bin ffuf; \
    curl -fsSLO "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_amd64.zip" && \
      unzip -q -o nuclei_*.zip -d /usr/local/bin nuclei && \
      chmod +x /usr/local/bin/nuclei; \
    curl -fsSLO "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VER}/dalfox-v${DALFOX_VER}-linux-x86_64.tar.gz" && \
      tar -xzf "dalfox-v${DALFOX_VER}-linux-x86_64.tar.gz" -C /usr/local/bin \
        --strip-components=1 "dalfox-v${DALFOX_VER}-linux-x86_64/dalfox"; \
    curl -fsSLO "https://github.com/epi052/feroxbuster/releases/download/v${FEROX_VER}/x86_64-linux-feroxbuster.tar.gz" && \
      tar -xzf x86_64-linux-feroxbuster.tar.gz -C /usr/local/bin feroxbuster; \
    rm -f /tmp/*.tar.gz /tmp/*.zip
RUN apt-get update && apt-get install -y --no-install-recommends \
      gobuster php-curl php-mbstring php-xml php-gd \
 && rm -rf /var/lib/apt/lists/*

# ★ nuclei 는 항상 -duc (업데이트 확인 비활성). 오프라인에서 매번 타임아웃 대기하는 것을 막는다.
ENV NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates
RUN printf '#!/bin/sh\nexec /usr/local/bin/nuclei -duc -t "$NUCLEI_TEMPLATES_DIR" "$@"\n' \
      > /usr/local/bin/nuclei-run && chmod +x /usr/local/bin/nuclei-run

RUN uv venv /opt/venvs/mitm \
 && VIRTUAL_ENV=/opt/venvs/mitm uv pip install mitmproxy \
 && for b in mitmproxy mitmdump mitmweb; do ln -sf "/opt/venvs/mitm/bin/$b" "/usr/local/bin/$b"; done
ARG JWT_TOOL_REF=3bc7407cf2222d6a821dcc19c776e5a1b1cb9a9b
RUN git init /opt/ctf-tools/jwt_tool \
 && git -C /opt/ctf-tools/jwt_tool remote add origin \
      https://github.com/ticarpi/jwt_tool \
 && git -C /opt/ctf-tools/jwt_tool fetch --depth=1 origin \
      "${JWT_TOOL_REF}" \
 && git -C /opt/ctf-tools/jwt_tool checkout --detach FETCH_HEAD \
 && uv venv /opt/venvs/jwt \
 && VIRTUAL_ENV=/opt/venvs/jwt uv pip install termcolor cprint pycryptodomex requests \
 && printf '#!/bin/sh\nexec /opt/venvs/jwt/bin/python /opt/ctf-tools/jwt_tool/jwt_tool.py "$@"\n' \
      > /usr/local/bin/jwt_tool && chmod +x /usr/local/bin/jwt_tool

# Playwright + Chromium
# ★ root 실행이라 --no-sandbox 필수. 런타임에 --shm-size=1g 도 필요.
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/playwright
RUN uv venv /opt/venvs/pw \
 && VIRTUAL_ENV=/opt/venvs/pw uv pip install playwright \
 && /opt/venvs/pw/bin/playwright install --with-deps --only-shell chromium \
 && ln -sf /opt/venvs/pw/bin/playwright /usr/local/bin/playwright \
 && printf '%s\n' \
      '#!/usr/bin/env bash' \
      'set -euo pipefail' \
      'if (($# == 0)); then' \
      '  printf "Usage: pw-python SCRIPT.py [ARGS...] | pw-python -c CODE\\n" >&2' \
      '  exit 2' \
      'fi' \
      'exec /opt/venvs/pw/bin/python "$@"' \
      > /usr/local/bin/pw-python \
 && printf '%s\n' \
      '#!/usr/bin/env bash' \
      'set -euo pipefail' \
      'if (($# == 0)); then' \
      '  printf "Usage: web-python SCRIPT.py [ARGS...] | web-python -c CODE\\n" >&2' \
      '  exit 2' \
      'fi' \
      'exec /opt/venvs/main/bin/python "$@"' \
      > /usr/local/bin/web-python \
 && chmod 0755 /usr/local/bin/pw-python /usr/local/bin/web-python

# 역직렬화 가젯 체인
ARG YSOSERIAL_VER=0.0.6
ARG PHPGGC_REF=f8aebde3a1abb88b02042fd12a71b4c61d6cfe2c
RUN mkdir -p /opt/ctf-tools/gadgets && cd /opt/ctf-tools/gadgets \
 && curl -fsSL -o ysoserial.jar \
      "https://github.com/frohoff/ysoserial/releases/download/v${YSOSERIAL_VER}/ysoserial-all.jar" \
 && printf '#!/bin/sh\nexec java -jar /opt/ctf-tools/gadgets/ysoserial.jar "$@"\n' > /usr/local/bin/ysoserial \
 && chmod +x /usr/local/bin/ysoserial \
 && git init /opt/ctf-tools/gadgets/phpggc \
 && git -C /opt/ctf-tools/gadgets/phpggc remote add origin \
      https://github.com/ambionics/phpggc \
 && git -C /opt/ctf-tools/gadgets/phpggc fetch --depth=1 origin \
      "${PHPGGC_REF}" \
 && git -C /opt/ctf-tools/gadgets/phpggc checkout --detach FETCH_HEAD \
 && ln -sf /opt/ctf-tools/gadgets/phpggc/phpggc /usr/local/bin/phpggc

# ─────────────────────────────────────────────────────────────────────────
# MISC / STEGO / ML
# ─────────────────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
      steghide outguess pngcheck jpeginfo imagemagick \
      ffmpeg sox libsox-fmt-all zbar-tools qrencode graphviz \
      multimon-ng minimodem \
 && rm -rf /var/lib/apt/lists/*

ARG BKCRACK_VER=1.8.1
ARG BKCRACK_SHA256=45dc7d81adbaaad5c0aa2d8615ea920fd08b732fda1ea945504e0a3e8dc1d2ab
RUN curl -fsSL -o /tmp/bkcrack.tar.gz \
      "https://github.com/kimci86/bkcrack/releases/download/v${BKCRACK_VER}/bkcrack-${BKCRACK_VER}-Linux-x86_64.tar.gz" \
 && echo "${BKCRACK_SHA256}  /tmp/bkcrack.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/bkcrack.tar.gz -C /usr/local/bin \
      --strip-components=1 "bkcrack-${BKCRACK_VER}-Linux-x86_64/bkcrack" \
 && chmod 0755 /usr/local/bin/bkcrack \
 && rm /tmp/bkcrack.tar.gz \
 && bkcrack --version | grep -F "${BKCRACK_VER}"

ARG STEGSEEK_REF=0e10a674b326298c5d51af8f2f7219ccac45e123
RUN git init /tmp/stegseek \
 && git -C /tmp/stegseek remote add origin \
      https://github.com/RickdeJager/stegseek \
 && git -C /tmp/stegseek fetch --depth=1 origin "${STEGSEEK_REF}" \
 && git -C /tmp/stegseek checkout --detach FETCH_HEAD \
 && cmake -S /tmp/stegseek -B /tmp/stegseek/build -DCMAKE_BUILD_TYPE=Release \
 && cmake --build /tmp/stegseek/build --target install -j"$(nproc)" \
 && stegseek --version 2>&1 | grep -F 'StegSeek 0.6' \
 && rm -rf /tmp/stegseek

# 자동 시도 도구 — ★ 출력이 많다. ctfwrap 을 반드시 경유시킬 것.
RUN uv venv /opt/venvs/stego \
 && VIRTUAL_ENV=/opt/venvs/stego uv pip install stegoveritas librosa \
 && ln -sf /opt/venvs/stego/bin/stegoveritas /usr/local/bin/stegoveritas \
 && /opt/venvs/stego/bin/stegoveritas_install_deps
# Ares 프로젝트는 crates.io 에 ciphey 패키지/바이너리로 배포된다.
RUN cargo install --locked --version 0.12.0 --root /usr/local ciphey

# PyTorch — CUDA 휠. GPU 없는 머신에서도 정상 동작하며 CPU 로 폴백된다.
RUN uv venv /opt/venvs/ml \
 && VIRTUAL_ENV=/opt/venvs/ml uv pip install \
      torch torchvision --index-url https://download.pytorch.org/whl/cu132 \
 && VIRTUAL_ENV=/opt/venvs/ml uv pip install transformers scikit-learn \
 && ln -sf /opt/venvs/ml/bin/python /usr/local/bin/ml-python
# Hashcat은 CUDA 드라이버와 함께 libnvrtc.so의 비버전 이름을 찾는다.
# NVRTC는 컴파일 시 versioned builtins를 basename으로 다시 연다. 두 파일을
# 모두 PyTorch CUDA 휠에서 노출해 별도 CUDA toolkit 없이 같은 런타임을 쓴다.
RUN set -eux; \
    CUDA_WHEEL_LIB="$(find /opt/venvs/ml -type f -name libnvrtc.so.13 \
      -printf '%h\n' -quit)"; \
    test -n "${CUDA_WHEEL_LIB}"; \
    test -f "${CUDA_WHEEL_LIB}/libcudart.so.13"; \
    CUDA_NVRTC_BUILTINS="$(find "${CUDA_WHEEL_LIB}" -maxdepth 1 -type f \
      -name 'libnvrtc-builtins.so.*' -print -quit)"; \
    test -n "${CUDA_NVRTC_BUILTINS}"; \
    install -d -m 0755 /usr/local/lib/ctf-cuda; \
    ln -s "${CUDA_WHEEL_LIB}/libnvrtc.so.13" \
      /usr/local/lib/ctf-cuda/libnvrtc.so; \
    ln -s "${CUDA_WHEEL_LIB}/libnvrtc.so.13" \
      /usr/local/lib/ctf-cuda/libnvrtc.so.1; \
    ln -s "${CUDA_WHEEL_LIB}/libcudart.so.13" \
      /usr/local/lib/ctf-cuda/libcudart.so; \
    ln -s "${CUDA_NVRTC_BUILTINS}" \
      "/usr/local/lib/ctf-cuda/$(basename "${CUDA_NVRTC_BUILTINS}")"
ENV LD_LIBRARY_PATH="/usr/local/lib/ctf-cuda"
RUN unlink /usr/local/bin/ml-python \
 && printf '#!/bin/sh\nexec /opt/venvs/ml/bin/python "$@"\n' > /usr/local/bin/ml-python \
 && chmod +x /usr/local/bin/ml-python \
 && /usr/local/bin/ml-python -c 'import torch; print(torch.__version__)' \
 && unlink /usr/local/bin/angr-python \
 && printf '#!/bin/sh\nexec /opt/venvs/angr/bin/python "$@"\n' > /usr/local/bin/angr-python \
 && chmod +x /usr/local/bin/angr-python \
 && /usr/local/bin/angr-python -c 'import angr; print(angr.__version__)' \
 && ln -sf /opt/venvs/docs/bin/oleid /usr/local/bin/oleid \
 && ln -sf /opt/venvs/docs/bin/olevba /usr/local/bin/olevba \
 && ln -sf /opt/venvs/docs/bin/peepdf /usr/local/bin/peepdf \
 && ln -sf /opt/venvs/docs/bin/msoffcrypto-tool /usr/local/bin/msoffcrypto-tool \
 && ln -sf /opt/venvs/docs/bin/rtfobj /usr/local/bin/rtfobj \
 && ln -sf /opt/venvs/docs/bin/oleobj /usr/local/bin/oleobj \
 && sed -i '1i#!/usr/bin/env python3' /usr/local/bin/pyinstxtractor.py \
 && chmod +x /usr/local/bin/pyinstxtractor.py \
 && command -v oleid olevba peepdf msoffcrypto-tool rtfobj oleobj \
      pyinstxtractor.py >/dev/null

# 에이전트가 실수로 인자 없이 실행했을 때 전체 /work 스캔, 패킷 캡처,
# 프록시 서버, curses TUI, QEMU 모니터로 진입하지 않게 한다. 원본은 PATH
# 밖에 보존하고 guard는 허용된 인자를 한 글자도 바꾸지 않고 그대로 전달한다.
RUN set -eux; \
    install -d -m 0755 /usr/local/libexec/ctf-os; \
    mv /usr/local/bin/ciphey /usr/local/libexec/ctf-os/ciphey.real; \
    ln -s /usr/bin/clamscan /usr/local/libexec/ctf-os/clamscan.real; \
    ln -s /usr/bin/ngrep /usr/local/libexec/ctf-os/ngrep.real; \
    ln -s /usr/bin/tcpdump /usr/local/libexec/ctf-os/tcpdump.real; \
    ln -s /usr/bin/photorec /usr/local/libexec/ctf-os/photorec.real; \
    ln -s /usr/bin/testdisk /usr/local/libexec/ctf-os/testdisk.real; \
    for architecture in aarch64 arm mips x86_64; do \
      ln -s "/usr/bin/qemu-system-${architecture}" \
        "/usr/local/libexec/ctf-os/qemu-system-${architecture}.real"; \
    done; \
    ln -s /opt/venvs/mitm/bin/mitmdump /usr/local/libexec/ctf-os/mitmdump.real; \
    unlink /usr/local/bin/mitmdump; \
    printf '%s\n' \
      '#!/usr/bin/env bash' \
      'set -euo pipefail' \
      '' \
      'tool=${0##*/}' \
      'real="/usr/local/libexec/ctf-os/${tool}.real"' \
      '' \
      'usage() {' \
      '  case "${tool}" in' \
      '    ciphey)   printf "Usage: ciphey [OPTIONS] (--text TEXT | --file PATH)\\n" >&2 ;;' \
      '    clamscan) printf "Usage: clamscan [OPTIONS] FILE...\\n" >&2 ;;' \
      '    ngrep)    printf "Usage: ngrep [OPTIONS] PATTERN [BPF-FILTER]\\n" >&2 ;;' \
      '    tcpdump)  printf "Usage: tcpdump [OPTIONS] (-r FILE | -i INTERFACE ...)\\n" >&2 ;;' \
      '    mitmdump) printf "Usage: mitmdump [OPTIONS] (explicit options required; use ctf-bg for server mode)\\n" >&2 ;;' \
      '    photorec) printf "Usage: photorec [OPTIONS] /cmd DEVICE COMMANDS\\n" >&2 ;;' \
      '    testdisk) printf "Usage: testdisk (/list [OPTIONS] [DEVICE] | [OPTIONS] /cmd DEVICE COMMANDS)\\n" >&2 ;;' \
      '    qemu-system-*) printf "Usage: %s [OPTIONS] (explicit machine or image options required)\\n" "${tool}" >&2 ;;' \
      '    *)        printf "ctf-tool-guard: unsupported invocation name: %s\\n" "${tool}" >&2 ;;' \
      '  esac' \
      '}' \
      '' \
      'case "${tool}" in' \
      '  ciphey|clamscan|ngrep|tcpdump|mitmdump|photorec|testdisk|qemu-system-aarch64|qemu-system-arm|qemu-system-avr|qemu-system-mips|qemu-system-riscv64|qemu-system-x86_64) ;;' \
      '  *) usage; exit 126 ;;' \
      'esac' \
      '[[ -x "${real}" ]] || { printf "%s: preserved executable is unavailable: %s\\n" "${tool}" "${real}" >&2; exit 127; }' \
      'if (($# == 0)); then' \
      '  usage' \
      '  exit 2' \
      'fi' \
      '' \
      'if [[ "${tool}" == photorec || "${tool}" == testdisk ]]; then' \
      '  unattended=0' \
      '  case "$1" in' \
      '    -h|--help|/help|"/?"|/version|--version) unattended=1 ;;' \
      '    /list) [[ "${tool}" == testdisk ]] && unattended=1 ;;' \
      '  esac' \
      '  for argument in "$@"; do' \
      '    [[ "${argument}" == /cmd ]] && unattended=1' \
      '  done' \
      '  if ((unattended == 0)); then' \
      '    printf "%s: interactive TUI mode is disabled; use /cmd%s\\n" "${tool}" "$([[ "${tool}" == testdisk ]] && printf " or /list")" >&2' \
      '    exit 2' \
      '  fi' \
      'fi' \
      '' \
      'exec "${real}" "$@"' \
      > /usr/local/libexec/ctf-os/noninteractive-guard; \
    chmod 0755 /usr/local/libexec/ctf-os/noninteractive-guard; \
    for tool in ciphey clamscan ngrep tcpdump mitmdump photorec testdisk \
        qemu-system-aarch64 qemu-system-arm qemu-system-mips \
        qemu-system-x86_64; do \
      ln -s ../libexec/ctf-os/noninteractive-guard "/usr/local/bin/${tool}"; \
      test "$(command -v -- "${tool}")" = "/usr/local/bin/${tool}"; \
      set +e; \
      timeout --signal=TERM --kill-after=1s 5s "${tool}" </dev/null >/dev/null 2>&1; \
      status=$?; \
      set -e; \
      test "${status}" -eq 2; \
    done; \
    for invocation in \
      'ciphey --help' \
      'clamscan --help' \
      'ngrep -h' \
      'tcpdump --help' \
      'mitmdump --help' \
      'photorec --help' \
      'photorec /version' \
      'testdisk --help' \
      'testdisk /version' \
      'testdisk /list'; do \
      set +e; \
      timeout --signal=TERM --kill-after=1s 5s bash -c \
        "${invocation} </dev/null >/dev/null 2>&1"; \
      status=$?; \
      set -e; \
      test "${status}" -ne 124; \
      test "${status}" -ne 137; \
    done; \
    set +e; \
    timeout --signal=TERM --kill-after=1s 5s photorec disk.img \
      </dev/null >/dev/null 2>&1; \
    photorec_status=$?; \
    timeout --signal=TERM --kill-after=1s 5s testdisk disk.img \
      </dev/null >/dev/null 2>&1; \
    testdisk_status=$?; \
    set -e; \
    test "${photorec_status}" -eq 2; \
    test "${testdisk_status}" -eq 2


############################################################
# STAGE 4: final — 자산 + 스크립트 + 인덱스
############################################################
FROM tools AS final

COPY --from=assets /assets/wordlists        /opt/wordlists
COPY --from=assets /assets/libc-database    /opt/ctf-tools/libc-database
COPY --from=assets /assets/volatility3      /opt/volatility3
COPY --from=assets /assets/nuclei-templates /opt/nuclei-templates
COPY --from=assets /assets/ctf-capability-fixtures /opt/ctf-capability-fixtures

RUN printf '%s\n' \
      '#!/bin/sh' \
      'cd /opt/ctf-tools/libc-database' \
      'exec ./identify "$@"' \
      > /usr/local/bin/libc-identify \
 && printf '%s\n' \
      '#!/bin/sh' \
      'cd /opt/ctf-tools/libc-database' \
      'exec ./find "$@"' \
      > /usr/local/bin/libc-find \
 && unlink /usr/local/bin/vol \
 && printf '%s\n' \
      '#!/bin/sh' \
      'exec /opt/venvs/vol3/bin/vol --symbol-dirs /opt/volatility3/symbols "$@"' \
      > /usr/local/bin/vol \
 && chmod 0755 /usr/local/bin/libc-identify /usr/local/bin/libc-find \
      /usr/local/bin/vol

# 빌드 캐시·문서·테스트·정적 링크 산출물은 런타임 기능이 아니다. CUDA
# 런타임, Sage 수학 패키지, 컴파일러, headless Chromium은 유지하면서
# 불필요한 런타임 파일만 정리한다.
RUN rm -rf /root/.cache /root/.cargo/registry /root/.cargo/git \
      /opt/mamba/pkgs \
      /opt/mamba/envs/sage/etc/conda/test-files \
      /opt/mamba/envs/sage/share/doc \
      /opt/mamba/envs/sage/share/giac/doc \
      /opt/mamba/envs/sage/share/gap/doc \
      /opt/mamba/envs/sage/share/jmol \
      /opt/mamba/envs/sage/share/threejs \
      /opt/mamba/envs/sage/share/jupyter \
      /opt/mamba/envs/sage/lib/jvm \
      /opt/john/src \
      /opt/ghidra/docs \
 && rm -f \
      /opt/wordlists/SecLists/Passwords/Leaked-Databases/rockyou.txt.tar.gz \
      /opt/wordlists/SecLists/Passwords/Leaked-Databases/rockyou-withcount.txt.tar.gz \
 && find /opt -type d -name .git -prune -exec rm -rf '{}' + \
 && find /opt/mamba/envs/sage /opt/zeek -xdev -type f -name '*.a' -delete \
 && sage -c 'R.<x> = PolynomialRing(GF(101)); assert factor(x^2 - 1); assert matrix(ZZ, [[1, 2], [3, 4]]).LLL().nrows() == 2' \
 && /opt/mamba/envs/sage/bin/python -c \
      'import cuso; from Crypto.Util.number import long_to_bytes' \
 && /opt/venvs/main/bin/python -c \
      'import bs4, cysignals, fpylll, gf2bv, h2, h2spacex, lxml, pysat, websockets' \
 && cargo --version >/dev/null \
 && /usr/local/bin/ml-python -c 'import torch; print(torch.__version__)' \
 && john --list=build-info >/dev/null \
 && zeek --version >/dev/null \
 && /opt/venvs/pw/bin/python -c 'from playwright.sync_api import sync_playwright; p = sync_playwright().start(); b = p.chromium.launch(headless=True); page = b.new_page(); page.set_content("<title>ctf-os</title>"); assert page.title() == "ctf-os"; b.close(); p.stop()' \
 && for extension in curl mbstring dom SimpleXML gd; do \
      php -m | grep -Fxi "${extension}" >/dev/null; \
    done \
 && command -v \
      bkcrack cryptominisat5 crypto-python evtxexport ewfinfo ewfverify \
      fls fsstat hash_extender icat \
      minimodem msoffcrypto-tool multimon-ng objdump oleobj pahole \
      pdfdetach pdfimages pydisasm pw-python qemu-img \
      qemu-system-aarch64 qemu-system-mips qpdf rabin2 radiff2 \
      regfexport ropr rtfobj sage-python socat uncompyle6 unsquashfs \
      wasm2wat wasm-opt web-python wine >/dev/null \
 && find /opt /usr /root -xdev -type f -name '*.pyc' -delete \
 && find /opt /usr /root -xdev -depth -type d -name __pycache__ -empty -delete \
 && rm -rf /root/.cache /tmp/*

# 작은 offline architecture/DFIR 보강은 비싼 기존 tool build cache를 보존하도록
# final stage의 독립 layer에 둔다. daemon, GUI, binfmt 등록은 설치하지 않는다.
RUN apt-get update && apt-get install -y --no-install-recommends \
      bc bison libelf-dev kmod device-tree-compiler ovmf \
      binutils-avr gcc-avr avr-libc gdb-avr simavr qemu-system-misc \
      libc6-dev-mips-cross libc6-dev-mipsel-cross libc6-dev-riscv64-cross \
      libscca-utils \
 && rm -rf /var/lib/apt/lists/* \
 && command -v \
      aarch64-linux-gnu-gcc arm-linux-gnueabihf-gcc \
      avr-gcc avr-gdb avr-objdump dtc mactime \
      mips-linux-gnu-gcc mipsel-linux-gnu-gcc modinfo \
      qemu-aarch64-static qemu-mips-static qemu-mipsel-static \
      qemu-riscv64-static qemu-system-avr qemu-system-riscv64 \
      riscv64-linux-gnu-gcc sccainfo simavr usnjls >/dev/null

# 새 system emulators도 기존 noninteractive guard 계약을 그대로 사용한다.
RUN set -eux; \
    for architecture in avr riscv64; do \
      ln -s "/usr/bin/qemu-system-${architecture}" \
        "/usr/local/libexec/ctf-os/qemu-system-${architecture}.real"; \
      ln -s ../libexec/ctf-os/noninteractive-guard \
        "/usr/local/bin/qemu-system-${architecture}"; \
      test "$(command -v -- "qemu-system-${architecture}")" = \
        "/usr/local/bin/qemu-system-${architecture}"; \
      set +e; \
      timeout --signal=TERM --kill-after=1s 5s \
        "qemu-system-${architecture}" </dev/null >/dev/null 2>&1; \
      status=$?; \
      set -e; \
      test "${status}" -eq 2; \
      "qemu-system-${architecture}" --version | \
        grep -F 'QEMU emulator version' >/dev/null; \
    done

# The engine runs challenge containers as the host uid. The global dotnet tool
# shim installed below /root is otherwise present in the root-built manifest
# but unreachable in production. Copy the complete tool store to a prefix
# traversable by non-root users and prove the shim works as an unprivileged uid.
RUN install -d -m 0755 /opt/dotnet-tools \
 && cp -a /root/.dotnet/tools/. /opt/dotnet-tools/ \
 && setpriv --reuid=65534 --regid=65534 --clear-groups \
      env HOME=/tmp DOTNET_CLI_HOME=/tmp \
      /opt/dotnet-tools/ilspycmd --version \
      | grep -F "${ILSPYCMD_VER}"
ENV PATH="/opt/dotnet-tools:${PATH}"

# 래퍼·인덱스·잡 시스템 (별도 산출물)
#   ctfwrap, ctf-bg, ctf-jobs, ctf-log, ctf-kill, ctf-idle, ctf-tools,
#   ctf-flag, ctf-browser, ctf-web-probe, ctf-egress-proxy,
#   ctf-network-smoke, ktext, ghidra-decompile, entrypoint.sh
COPY scripts/ /usr/local/bin/
RUN chmod +x /usr/local/bin/ctf* /usr/local/bin/ktext /usr/local/bin/ghidra-decompile \
             /usr/local/bin/entrypoint.sh /usr/local/bin/gen-manifest.sh
COPY capabilities.v2.json /tools/capabilities.json

# 템플릿 라이브러리
COPY templates/ /opt/ctf-templates/
RUN find /opt/ctf-templates -type f \
      \( -name '*.sh' -o -name '*.py' -o -name '*.sage' \) \
      -exec chmod 0755 '{}' +

# 도구 인덱스 — 빌드 시점에 실제 실행해서 생성한다. 손으로 쓰지 말 것.
RUN /usr/bin/python3 /opt/ctf-templates/forensic/evidence_index.py \
      --help >/dev/null \
 && /usr/local/bin/gen-manifest.sh > /tools/manifest.json \
 && jq -e '.schema_version == 1 \
      and (.failed | type == "array" and length == 0) \
      and (.tools | type == "array" and length > 0) \
      and all(.tools[]; .available == true and (.path | startswith("/"))) \
      and ((["ctfwrap", "ctf-bg", "ctf-jobs", "ctf-log", "ctf-kill", "ctf-idle", "ctf-tools", "ctf-flag", "ctf-browser", "ctf-web-probe", "ctf-egress-proxy", "ctf-network-smoke", "ctf-sqlite-readonly", "ktext", "ghidra-decompile"] - [.tools[].name]) | length == 0)' \
      /tools/manifest.json >/dev/null \
 && python3 /usr/local/bin/ctf-tools --render-md > /tools/TOOLS.md \
 && python3 /usr/local/bin/ctf-tools --json --info ctfwrap \
      | jq -e '.found == true and .tool.available == true' >/dev/null \
 && /usr/local/bin/ctf-capabilities --json \
      | jq -e '.schema_version == 2 \
          and (.capabilities | length == 35) \
          and all(.capabilities[]; .available == true) \
          and ([.capabilities[] \
              | select(.name == "web_response_summary_v1" \
                  or .name == "pwn_crash_v1" \
                  or .name == "pwn_runtime_snapshot_v1" \
                  or .name == "pwn_exploit_effect_v1" \
                  or .name == "pwn_interaction_v1" \
                  or .name == "rev_inventory_v2" \
                  or .name == "rev_safe_output" \
                  or .name == "rev_stdin_exec" \
                  or .name == "rev_runtime_exec_v1" \
                  or .name == "data_transcript_v1" \
                  or .name == "forensic_evidence_index_v1") \
              | .attestation.schema_version] == [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])' >/dev/null \
 && rm -f /tools/failed.txt

# 실행 환경
ENV FLAG_REGEX='[A-Za-z0-9_]{2,20}\{[^}\r\n]{1,200}\}'
WORKDIR /work

# entrypoint: /challenge(ro) → /work 복사, 원본 해시 기록
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["ctf-idle", "--serve"]
