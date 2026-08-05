# PETS — Privilege Escalation Tool Suggester

> `wes.py` 는 **무엇이 취약한지**를 알려준다. **PETS** 는 **그래서 무엇으로 뚫는지**를 알려준다.

OSCP/CPTS 실습이나 인가된 모의해킹에서 [wes.py (Windows-Exploit-Suggester-NG)](https://github.com/bitsadmin/wesng)
결과는 CVE 가 수십~수백 개씩 쏟아져 실제로 쓸만한 게 뭔지 고르기 힘들다.

PETS 는 wes.py 출력을 파싱해 CVE 를 인식하고, **실제로 존재하는 익스플로잇 도구/PoC**
— JuicyPotato · PrintSpoofer · GodPotato · RoguePotato · Churrasco · `Invoke-MS16-032.ps1`
· 각종 커널 LPE `.exe` 등 — 로 연결해 **우선순위로 정리**해 준다.

## 특징

- **CVE → 실제 도구 매핑**: 확장 가능한 지식베이스(`exploit_db.json`)에 CVE, 별칭(MS16-032 등),
  대상 OS, 도구 종류(`exe`/`ps1`/`py`/`msf`), 배포 URL, 사용 노트를 담았다.
- **노이즈 제거 + 우선순위화**: 바로 실행 가능한 도구(exe/ps1)와 권한상승 영향(EoP/Domain Admin)이
  큰 CVE 를 위로 정렬. 도구 미매핑 CVE 는 접어 둔다(`--show-all` 로 전체).
- **권한 기반 기법 안내(Potato 계열)**: CVE 와 무관하게 `SeImpersonatePrivilege` 보유 시
  쓰는 PrintSpoofer/GodPotato/JuicyPotato 등을 탐지 OS 에 맞춰 항상 함께 추천.
- **입력 형식 자동 감지**: wes.py 기본 텍스트 출력과 CSV(`-o out.csv`) 모두 지원.
- **의존성 없음**: Python 3 표준 라이브러리만 사용. `--json` 으로 결과 내보내기 가능.

## 사용법

```bash
# 1) 대상에서 systeminfo 수집
systeminfo > systeminfo.txt

# 2) wes.py 로 취약점 탐지
python3 wes.py systeminfo.txt -o wes_out.txt      # 또는 -o wes_out.csv

# 3) PETS 로 실제 익스플로잇 도구 추천
python3 pets.py wes_out.txt
```

### 옵션

| 옵션 | 설명 |
|------|------|
| `--show-all` | 도구가 매핑되지 않은 CVE 도 전부 표시 |
| `--json FILE` | 결과를 JSON 으로 저장 (자동화/연동용) |
| `--db PATH` | 지식베이스 JSON 경로 지정 (기본: 스크립트 옆 `exploit_db.json`) |
| `--no-color` | ANSI 색상 끄기 (파이프/리다이렉트 시 자동 비활성) |

## 출력 구조

1. **우선순위 CVE** — 익스플로잇 도구가 존재하는 CVE. 도구명/종류/URL/노트 포함.
2. **권한 기반 기법(Potato 계열)** — `whoami /priv` 로 `SeImpersonatePrivilege` 확인 후 사용.
3. **도구 미매핑 CVE** — 기본은 wes.py 자체 익스플로잇 링크가 있는 것만, `--show-all` 로 전체.

예시 실행 결과는 [`examples/`](examples/) 의 샘플 파일로 확인할 수 있다.

```bash
python3 pets.py examples/sample_wes_output.txt
python3 pets.py examples/sample_wes_output.csv --show-all
```

## 지식베이스 확장하기

`exploit_db.json` 의 `cve_map` 에 항목을 추가하면 바로 반영된다.

```json
"CVE-2024-XXXXX": {
  "aliases": ["별칭"],
  "name": "취약점 설명",
  "impact": "Elevation of Privilege",
  "technique": "kernel-win32k",
  "os": "대상 OS",
  "tools": [
    {"name": "도구명", "type": "exe", "url": "https://github.com/...", "note": "사용 팁"}
  ],
  "refs": ["https://..."]
}
```

`type` 값: `exe`(컴파일 바이너리) · `ps1`(PowerShell) · `py`(Python) · `c`(소스) ·
`msf`(Metasploit) · `manual`(수동 기법). exe/ps1 은 정렬 시 가산점을 받는다.

## 수록 도구 (일부)

**커널/LPE PoC**: MS16-032(CVE-2016-0099) · MS15-051(CVE-2015-1701) · MS14-058(CVE-2014-4113) ·
MS14-068(CVE-2014-6324) · KiTrap0D(CVE-2010-0232) · CVE-2020-0668 · CVE-2020-0787 · CVE-2020-0796(SMBGhost) ·
CVE-2021-1732 · CVE-2022-21882 · CVE-2023-21768(afd.sys) · CVE-2023-28252(CLFS) · CVE-2021-40449 ·
HiveNightmare(CVE-2021-36934) · PrintNightmare(CVE-2021-1675/34527) · Zerologon(CVE-2020-1472) 외

**권한 기반(Potato 계열)**: PrintSpoofer · GodPotato · JuicyPotato · RoguePotato · SweetPotato ·
RottenPotatoNG · EfsPotato · SigmaPotato · Churrasco

## 면책 / Legal

PETS 는 **인가된** 모의해킹, CTF, OSCP/CPTS 등 학습 목적의 참고 도구다.
추천된 익스플로잇을 실행하기 전에 반드시 대상에 대한 정당한 권한을 확인할 것.
본 도구 및 연결된 익스플로잇 사용에 따른 책임은 사용자 본인에게 있다.

## 라이선스

MIT
