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
- **커널은 최후 수단**: 커널 익스플로잇은 BSOD/리셋 위험이 있어 실전·시험 권장 순서상 마지막이다.
  PETS 는 커널 항목(`technique: kernel-*`)에 페널티를 줘 하위로 내리고 `[커널·최후수단]` 태그를 붙인다.
  서비스 오구성·권한남용(Potato)·자격증명 같은 비커널 경로를 먼저 노출한다.
- **권한 기반 기법 안내(Potato 계열)**: CVE 와 무관하게 `SeImpersonatePrivilege` 보유 시
  쓰는 PrintSpoofer/GodPotato/JuicyPotato 등을 탐지 OS 에 맞춰 항상 함께 추천.
- **입력 형식 자동 감지**: wes.py 기본 텍스트 출력과 CSV(`-o out.csv`) 모두 지원. wes 버전별
  헤더 차이(`Affected product` vs `AffectedProduct`, `Exploit` vs `Exploits`, `KB` vs `BulletinKB`)를
  정규화해 처리한다.
- **OS 인지 Potato 추천**: 탐지된 OS 에 맞는 권한 기반 도구만 노출. 예를 들어 Server 2003 박스에서는
  Churrasco 만 보여 주고 JuicyPotato/PrintSpoofer 등 최신 도구는 숨긴다.
- **적용 범위(scope) 뱃지**: 각 CVE 가 단독 호스트용인지 AD(도메인) 전용인지 표시한다.
  - `[로컬]` — 단독(standalone) 호스트에서 동작하는 로컬 권한상승(LPE)
  - `[로컬+AD]` — 둘 다 가능 (예: PrintNightmare 는 로컬 관리자 추가 + 원격/도메인 악용 모두 가능)
  - `[AD 전용]` — Zerologon · MS14-068 · noPac · PetitPotam 처럼 **도메인 컨트롤러/AD 가 있어야** 동작.
    단독 박스에서는 무의미하므로 요약에 별도 경고를 띄운다.
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
| `--ad` | **AD 모드**: BloodHound(bloodhound-python) JSON 을 분석해 권한상승 엣지 → 도구 추천 |
| `--json-path DIR` | `[--ad 필수]` bloodhound-python JSON 들이 있는 디렉터리(또는 단일 파일) |
| `--owned ACCT` | `[--ad]` 장악한 계정(들). `user` 또는 `user:pass`, 콤마 구분. 즉시 악용 가능한 엣지 강조 + 명령 치환 |
| `--dc HOST` | `[--ad]` 예시 명령에 넣을 DC 호스트명 (기본: `dc01`) |
| `--domain DOM` | `[--ad]` 예시 명령에 넣을 도메인 (기본: 데이터에서 자동 감지) |
| `--show-all` | 도구가 매핑되지 않은 CVE 도 전부 표시 |
| `--json FILE` | 결과를 JSON 으로 저장 (자동화/연동용, wes·AD 모드 공통) |
| `--db PATH` | CVE 지식베이스 경로 지정 (기본: 스크립트 옆 `exploit_db.json`) |
| `--ad-db PATH` | AD 엣지 지식베이스 경로 지정 (기본: 스크립트 옆 `ad_edges.json`) |
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

## AD 모드 (`--ad`): BloodHound 엣지 → 실제 공격 도구

로컬 권한상승과 똑같은 철학을 AD 에도 적용한다. BloodHound 그래프를 눈으로 훑는 대신,
`bloodhound-python` 이 뽑은 JSON 을 읽어 **악용 가능한 권한상승 엣지를 찾아 impacket/PowerView/
Certipy/Rubeus 명령까지 한국어로** 제시한다.

```bash
# 1) BloodHound 데이터 수집 (예)
bloodhound-python -u attacker -p 'Passw0rd!' -d corp.local -ns 10.10.10.10 -c All

# 2) 생성된 *_users.json / *_groups.json / *_computers.json ... 가 있는 폴더를 지정
python3 pets.py --ad --json-path ./  

# 예제 데이터로 확인
python3 pets.py --ad --json-path examples/bloodhound_sample
```

### 장악 계정 지정 (`--owned`)

내가 이미 손에 넣은 계정을 지정하면, **그 계정(및 소속 그룹, `Domain Users` 같은 저권한 그룹)이
지금 바로 악용할 수 있는 엣지를 최상위로 끌어올려 `★ 즉시 실행 가능`** 으로 강조한다.
동시에 예시 명령의 도메인·계정·DC 를 실제 값으로 치환해 바로 복붙할 수 있게 한다.

```bash
# 비번까지 주면 명령에 그대로 치환됨 (user:pass)
python3 pets.py --ad --json-path ./ --owned 'jdoe:Summer2026!' --dc dc01.corp.local

# 여러 계정 지정 가능 (콤마 구분)
python3 pets.py --ad --json-path ./ --owned 'jdoe,svc_sql'
```

출력 예 (`--owned 'jdoe:Summer2026!'`):

```
[OWNED] 소유 계정: jdoe  ->  지금 바로 악용 가능: 2종 2건

● ForceChangePassword (1건)  ... [★ 즉시 실행 가능] [저권한 주체]
    DOMAIN USERS@CORP.LOCAL --ForceChangePassword--> SVC_BACKUP@CORP.LOCAL [user] ★OWNED
    ▸ 대상이 사용자
      $ bloodyAD -u jdoe -p 'Summer2026!' -d corp.local --host dc01.corp.local set password TARGETUSER 'NewPass123!'
```

**탐지/추천하는 것:**

- **ACL 엣지** — `GenericAll` · `GenericWrite` · `WriteDacl` · `WriteOwner` · `Owns` ·
  `ForceChangePassword` · `AddMember` · `AllExtendedRights` · `AddKeyCredentialLink`(Shadow Cred) ·
  `ReadLAPSPassword` · `ReadGMSAPassword` · `AddAllowedToAct`(RBCD) · `WriteSPN` · GPO 쓰기
- **DCSync** — 도메인 객체의 `GetChanges` + `GetChangesAll` 조합을 자동 판정
- **속성 기반** — Kerberoastable(SPN) · AS-REP Roastable · 제약/무제약 위임 · PasswordNotReqd · SIDHistory
- **저권한 주체 강조** — `Domain Users`/`Authenticated Users`/`Everyone` 등이 가진 엣지를
  `[저권한 주체 포함!]` 로 최상위 강조 (누구나 악용 가능 = 최우선 확인 대상)

각 엣지마다 **무엇을 뜻하는지 + 대상 유형별 악용 절차 + 바로 복붙 가능한 명령 + 도구 링크**를
함께 출력한다. 우선순위(high/med/low)와 건수로 정렬된다.

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
