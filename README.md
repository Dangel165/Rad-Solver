# Rad Solver

CTF 문제를 자동으로 분석하고, 가능한 플래그 후보와 풀이 단서를 점수 기반으로 랭킹하는 로컬 전용 자동화 도구입니다.

> 범위: 합법적인 CTF/워게임/개인 실습 문제 분석용입니다. 실제 서비스 공격, 무단 스캔, 악성코드 제작/배포 자동화는 포함하지 않습니다.

## 지원 분야

- **Crypto**: base64/base32/base85/hex/url 인코딩, Caesar/ROT 암호, 반복 XOR, 단일 바이트 XOR, 재귀적 디코딩
- **Files**: 파일 매직 바이트 식별, 문자열 추출, PNG/JPEG/PDF/ELF/PE 메타데이터 분석
- **Reversing**: 바이너리 문자열 추출, 의심 API/패커/디버그 심볼 탐지, 테이블 기반 암호화 패턴 분석
- **Web**: HTML/JS/CSS 주석, JWT 토큰, 숨겨진 경로, 인코딩된 페이로드 추출
- **Forensics**: 파일 시그니처 식별, EXIF/PNG 메타데이터 추출, 스테가노그래피 탐지, 숨겨진 데이터 분석
- **Pwn**: 위험한 함수 탐지, ROP 가젯 분석, 바이너리 보호 확인, 익스플로잇 취약점 힌트

## 빠른 시작

```powershell
cd ctf_auto_solver_bot
py -m ctfbot --help
py -m ctfbot scan --input .\samples\base64_flag.txt
py -m ctfbot solve --input "ZmxhZ3t0ZXN0X2ZsYWd9"
```

GUI 실행:

```powershell
py -m ctfbot.gui
```

또는 배치파일 사용:

```powershell
.\install_libraries.bat
.\run_gui.bat
.\run_cli.bat scan --input .\samples\base64_flag.txt
```

처음부터 설치 후 GUI까지 바로 열기:

```powershell
.\quick_start.bat
```

결과를 JSON으로 저장:

```powershell
py -m ctfbot scan --input .\samples --json .\report.json
```

## 구조

```text
ctfbot/
  __main__.py        CLI 진입점
  gui.py             GUI 인터페이스
  engine.py          플러그인 실행 및 점수 랭킹 엔진
  models.py          결과 데이터 모델
  utils.py           공통 유틸리티
  plugins/           분야별 분석 플러그인
    crypto.py        암호화/인코딩 분석
    files.py         파일 포맷 및 메타데이터 분석
    reversing.py     바이너리 분석
    web.py           웹 콘텐츠 분석
    forensics.py     포렌식 분석
    pwn.py           익스플로잇 취약점 분석
tests/               테스트 코드
samples/             샘플 파일
```

## 정확도 향상 방법

이 도구는 한 번에 답을 단정하지 않고 여러 플러그인의 증거를 합산합니다.

- 플래그 정규식 패턴 매칭: 높은 점수
- 성공적으로 디코딩된 텍스트: 중간 점수
- 파일 타입/의심 함수/숨겨진 문자열: 힌트 점수
- 같은 후보가 여러 분석기에서 발견되면 자동 승격

새 CTF 플래그 형식이 있으면 `--flag-format` 옵션으로 추가하세요:

```powershell
py -m ctfbot scan --input .\challenge.bin --flag-format "CODEGATE\{[^}]+\}"
```

문제 설명이나 힌트를 제공하면 정확도가 향상됩니다:

```powershell
py -m ctfbot scan --input .\challenge.bin --prompt "리버싱 문제. flag format: KEYROOT{} password 문자열을 확인"
py -m ctfbot scan --input .\challenge.bin --prompt-file .\problem_statement.txt
```

## 사용 범위

이 도구는 로컬 파일 분석에만 사용됩니다. 네트워크 공격, 자동 익스플로잇, 또는 무단 스캔 기능은 포함하지 않습니다. 합법적인 CTF 대회, 워게임, 개인 실습 문제 분석에만 사용하세요.
