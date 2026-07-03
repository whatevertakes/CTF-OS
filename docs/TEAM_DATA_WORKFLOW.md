# 팀 데이터 워크플로

이 저장소의 목표는 Level 3 agent 설계에 사용할 수 있는 비교 가능한 CTF 풀이
데이터를 모으는 것입니다. 팀원은 프레임워크 변경이 아니라 정제된 챌린지
데이터를 제출합니다.

## 브랜치

`main`은 소유자 `jiwoongchoi-norun`만 push합니다. 팀원은 자기 이름의 고정
브랜치에만 commit/push합니다.

```text
shyunseok1029
holymo-ly
jiwoongchoi-norun
lee
```

처음 클론한 뒤 자기 브랜치를 체크아웃합니다.

```bash
git fetch origin
git switch --track origin/<github-user>
tools/team_member_setup.sh
```

`main` 업데이트를 자기 브랜치에 반영하려면 다음을 실행합니다.

```bash
git fetch origin
git switch <github-user>
git merge origin/main
```

승인된 데이터 파일만 commit합니다.

```text
benchmarks/*_SANITIZED_BENCHMARK_REPORT.md
benchmarks/*_DATA_MANIFEST.json
challenges/<event>/<category>/<challenge>/state.json
challenges/<event>/<category>/<challenge>/notes.md
challenges/<event>/<category>/<challenge>/replay.sh
challenges/<event>/<category>/<challenge>/evidence/*.summary.md
challenges/<event>/<category>/<challenge>/evidence/*.sanitize_check.md
```

raw flag, raw replay log, private key, `.env` 파일, challenge `work/` scratch
tree, dependency checkout, 프레임워크 파일은 commit하지 않습니다.

## 로컬 검증

PR을 열기 전에 다음을 실행합니다.

```bash
python3 tools/validate_data_submission.py --base origin/main
python3 tools/evaluate_corpus.py
```

staged 파일만 검증하려면:

```bash
python3 tools/validate_data_submission.py --staged
```

## Push 및 Pull Request

자기 브랜치에 push합니다.

```bash
git push origin HEAD:<github-user>
```

자기 브랜치에서 `main`으로 PR을 엽니다. data-submission GitHub Action은
`shyunseok1029`, `holymo-ly`, `jiwoongchoi-norun` 브랜치에서 올라온 PR이
승인된 정제 데이터 경로만 바꾸는지 검사합니다. 병합은 소유자 리뷰 후에만
진행합니다.

직접 브랜치 push가 불가능하면 benchmark data issue template을 사용하고 동일한
정제 파일을 첨부합니다.
