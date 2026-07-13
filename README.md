# CTF-OS

CTF-OS는 사람이 연 Sol/Luna 세션을 위한 로컬 CTF 분석 도구입니다. 사람은 문제 파일과 `problems.txt`만 준비하고, Intake가 내부 `contest.md` manifest 생성·검증·workspace 준비를 처리합니다.

## 시작

1. 저장소를 clone합니다.

   ```bash
   git clone git@github.com:whatevertakes/CTF-OS.git
   cd CTF-OS
   ```

2. 의존성을 설치합니다.

   ```bash
   uv sync --frozen
   ```

3. 환경을 확인합니다.

   ```bash
   uv run python -m ctf_os.agent_tools doctor
   ```

4. 대회 폴더를 만듭니다.

   ```bash
   uv run python -m ctf_os.agent_tools init-contest "My CTF 2026"
   ```

5. 문제 파일을 `incoming/<contest>/<category>/` 아래에 넣습니다.

6. `incoming/<contest>/problems.txt`에 문제 정보와 원격을 붙여 넣습니다. 생성된 파일의 주석 예시를 참고합니다.

7. Luna에게 **“intake 해”**라고 요청합니다.

Intake는 `problems.txt`를 읽고 실제 파일을 확인한 뒤 `contest.md`를 생성 또는 갱신하고, parser 검증·intake·workspace 준비를 완료합니다. `contest.md`는 내부 manifest이며 사람이 수정하지 않습니다.
