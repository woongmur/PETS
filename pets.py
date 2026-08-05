#!/usr/bin/env python3
"""
PETS - Privilege Escalation Tool Suggester
==========================================

wes.py (Windows-Exploit-Suggester-NG) 의 출력에서 CVE 를 인식하여,
실제로 존재하는 익스플로잇 도구/PoC (JuicyPotato, PrintSpoofer, GodPotato,
Churrasco, MS16-032.ps1, 각종 커널 LPE exe 등) 로 연결/추천해 준다.

wes.py 는 "무엇이 취약한지"를 알려주지만 결과가 너무 많다.
PETS 는 "그래서 무엇으로 권한상승을 할 수 있는지"를 우선순위로 정리해 준다.

사용법:
    python3 wes.py systeminfo.txt -o wes_out.txt        # wes.py 실행
    python3 pets.py wes_out.txt                         # PETS 로 매핑

    python3 pets.py wes_out.csv                         # CSV 출력도 지원
    python3 pets.py wes_out.txt --show-all              # 미매핑 CVE 도 표시
    python3 pets.py wes_out.txt --json result.json      # 결과 JSON 저장
    python3 pets.py wes_out.txt --no-color              # 색상 끄기

작성 목적: OSCP/CPTS 등 실습 및 인가된 모의해킹에서 도구 탐색 시간을 줄이기 위함.
"""

import argparse
import csv
import io
import json
import os
import re
import sys

# ---------------------------------------------------------------------------
# 색상 (외부 의존성 없이 ANSI 직접 사용)
# ---------------------------------------------------------------------------
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GREY = "\033[90m"

    @classmethod
    def disable(cls):
        for name in dir(cls):
            if name.isupper():
                setattr(cls, name, "")


BANNER = r"""
  ____  _____ _____ ____
 |  _ \| ____|_   _/ ___|    Privilege Escalation Tool Suggester
 | |_) |  _|   | | \___ \    wes.py CVE  ->  real exploit tools
 |  __/| |___  | |  ___) |
 |_|   |_____| |_| |____/    JuicyPotato / PrintSpoofer / GodPotato / kernel LPE
"""

# 심각도/영향 우선순위 점수 (정렬용)
IMPACT_WEIGHT = {
    "domain admin": 100,
    "elevation of privilege": 80,
    "local privilege escalation": 80,
    "remote code execution": 60,
    "rce": 60,
}

# wes.py 텍스트 블록의 필드 키
FIELD_KEYS = (
    "Date", "CVE", "KB", "Title",
    "Affected product", "Affected component",
    "Severity", "Impact", "Exploit",
)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


# ---------------------------------------------------------------------------
# DB 로딩
# ---------------------------------------------------------------------------
def load_db(path=None):
    if path is None:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "exploit_db.json")
    if not os.path.isfile(path):
        sys.exit(f"[!] 지식베이스를 찾을 수 없습니다: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# wes.py 출력 파싱 (텍스트 블록 / CSV 자동 감지)
# ---------------------------------------------------------------------------
def parse_wes(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()

    findings = _parse_csv(raw)
    if findings is None:
        findings = _parse_text(raw)
    return findings


# wes.py CSV 헤더는 버전에 따라 다르다:
#   구버전 텍스트/CSV: Date, KB, Affected product, Affected component, Exploit
#   신버전 CSV(-o out.csv): DatePosted, BulletinKB, AffectedProduct, AffectedComponent, Exploits
# 정규화(소문자+영숫자만) 후 별칭으로 매칭한다.
CSV_ALIASES = {
    "cve": ["cve"],
    "title": ["title"],
    "product": ["affectedproduct"],
    "severity": ["severity"],
    "impact": ["impact"],
    "exploit": ["exploits", "exploit"],
    "kb": ["bulletinkb", "kb"],
}


def _norm(s):
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def _parse_csv(raw):
    """CSV 형식이면 findings 리스트, 아니면 None 반환."""
    first_line = raw.lstrip().splitlines()[0] if raw.strip() else ""
    if "CVE" not in first_line.upper() or "," not in first_line:
        return None
    try:
        reader = csv.DictReader(io.StringIO(raw))
        rows = list(reader)
    except csv.Error:
        return None
    fieldnames = reader.fieldnames or []
    # 정규화된 헤더 -> 실제 헤더 매핑
    norm_map = {_norm(fn): fn for fn in fieldnames}
    if "cve" not in norm_map:
        return None

    def col(row, field):
        for alias in CSV_ALIASES[field]:
            real = norm_map.get(alias)
            if real is not None:
                return (row.get(real) or "").strip()
        return ""

    findings = []
    for row in rows:
        cve = col(row, "cve").upper()
        if not CVE_RE.fullmatch(cve):
            continue
        findings.append({
            "cve": cve,
            "title": col(row, "title"),
            "product": col(row, "product"),
            "severity": col(row, "severity"),
            "impact": col(row, "impact"),
            "exploit": col(row, "exploit"),
            "kb": col(row, "kb"),
        })
    return findings


def _parse_text(raw):
    """wes.py 기본 텍스트 출력(빈 줄로 구분된 Key: Value 블록) 파싱."""
    findings = []
    for block in re.split(r"\n\s*\n", raw):
        if "CVE:" not in block and not CVE_RE.search(block):
            continue
        fields = {}
        for line in block.splitlines():
            m = re.match(r"\s*([A-Za-z ]+):\s*(.*)$", line)
            if m and m.group(1).strip() in FIELD_KEYS:
                fields[m.group(1).strip()] = m.group(2).strip()

        cve = fields.get("CVE", "")
        if not cve:
            m = CVE_RE.search(block)
            cve = m.group(0) if m else ""
        if not cve:
            continue

        findings.append({
            "cve": cve.upper(),
            "title": fields.get("Title", ""),
            "product": fields.get("Affected product", ""),
            "severity": fields.get("Severity", ""),
            "impact": fields.get("Impact", ""),
            "exploit": fields.get("Exploit", ""),
            "kb": fields.get("KB", ""),
        })
    return findings


def dedupe(findings):
    """동일 CVE 는 하나로 합치되, 영향받는 제품 목록은 모은다."""
    merged = {}
    for f in findings:
        cve = f["cve"]
        if cve not in merged:
            merged[cve] = dict(f)
            merged[cve]["products"] = set()
        if f.get("product"):
            merged[cve]["products"].add(f["product"])
    for f in merged.values():
        f["products"] = sorted(f["products"])
    return list(merged.values())


# ---------------------------------------------------------------------------
# OS 힌트 추출 (Potato 계열 추천 정확도 향상용)
# ---------------------------------------------------------------------------
def detect_os(raw_findings, full_text=""):
    text = full_text + " " + " ".join(
        f.get("product", "") + " " + f.get("title", "") for f in raw_findings
    )
    text = text.lower()
    hints = []
    for pat, label in [
        (r"windows server 2003", "Server 2003"),
        (r"windows server 2008", "Server 2008"),
        (r"windows server 2012", "Server 2012"),
        (r"windows server 2016", "Server 2016"),
        (r"windows server 2019", "Server 2019"),
        (r"windows server 2022", "Server 2022"),
        (r"windows 7", "Windows 7"),
        (r"windows 8", "Windows 8"),
        (r"windows 10", "Windows 10"),
        (r"windows 11", "Windows 11"),
    ]:
        if re.search(pat, text):
            hints.append(label)
    return hints


def os_tokens(text):
    """OS 문자열에서 비교용 토큰 집합 추출 (Potato 적용 여부 판정)."""
    t = (text or "").lower()
    toks = set()
    for num in ("2000", "2003", "2008", "2012", "2016", "2019", "2022"):
        if num in t:
            toks.add(num)
    if re.search(r"\bxp\b", t):
        toks.add("xp")
    # 클라이언트 버전: "windows 7/8/10/11" 및 범위 표기의 양 끝 숫자
    for m in re.findall(r"(?<!\d)(11|10|8|7)(?!\d)", t):
        toks.add("win" + m)
    return toks


# ---------------------------------------------------------------------------
# 매핑
# ---------------------------------------------------------------------------
def is_kernel(db_entry):
    """커널 익스플로잇 여부 (technique 가 kernel-* 로 시작)."""
    return (db_entry.get("technique") or "").startswith("kernel")


def impact_score(finding):
    imp = (finding.get("impact") or "").lower().strip()
    sev = (finding.get("severity") or "").lower().strip()
    score = IMPACT_WEIGHT.get(imp, 0)
    if not score:
        for key, w in IMPACT_WEIGHT.items():
            if key in imp:
                score = max(score, w)
    if "critical" in sev:
        score += 5
    elif "important" in sev:
        score += 3
    return score


def map_findings(findings, db):
    cve_map = db.get("cve_map", {})
    mapped, unmapped = [], []
    for f in findings:
        entry = cve_map.get(f["cve"])
        if entry:
            f["db"] = entry
            mapped.append(f)
        else:
            unmapped.append(f)

    def sort_key(f):
        tool_bonus = 0
        for t in f["db"].get("tools", []):
            ttype = t.get("type", "")
            if ttype in ("ps1", "exe"):
                tool_bonus = 10  # 바로 실행 가능한 도구 우대
                break
        # 커널 익스플로잇은 최후 수단(BSOD 위험) -> 페널티로 하위 배치
        penalty = 25 if is_kernel(f["db"]) else 0
        return (-(impact_score(f) + tool_bonus - penalty), f["cve"])

    mapped.sort(key=sort_key)
    unmapped.sort(key=lambda f: (-impact_score(f), f["cve"]))
    return mapped, unmapped


# ---------------------------------------------------------------------------
# 출력
# ---------------------------------------------------------------------------
TYPE_LABEL = {
    "exe": f"{C.GREEN}[EXE]{C.RESET}",
    "ps1": f"{C.CYAN}[PS1]{C.RESET}",
    "py": f"{C.YELLOW}[PY ]{C.RESET}",
    "c": f"{C.YELLOW}[C  ]{C.RESET}",
    "msf": f"{C.MAGENTA}[MSF]{C.RESET}",
    "manual": f"{C.GREY}[MAN]{C.RESET}",
}


def _tlabel(ttype):
    return TYPE_LABEL.get(ttype, f"[{ttype.upper()[:3]:<3}]")


def scope_badge(scope):
    """익스플로잇 적용 범위 뱃지. domain=AD 필요, both=로컬+AD, local=단독 호스트."""
    if scope == "domain":
        return f"{C.RED}{C.BOLD}[AD 전용]{C.RESET}"
    if scope == "both":
        return f"{C.YELLOW}[로컬+AD]{C.RESET}"
    return f"{C.GREY}[로컬]{C.RESET}"


def print_report(mapped, unmapped, os_hints, potato_tools, show_all):
    print(f"{C.CYAN}{C.BOLD}{BANNER}{C.RESET}")

    total = len(mapped) + len(unmapped)
    ad_only = sum(1 for f in mapped if f["db"].get("scope") == "domain")
    print(f"{C.BOLD}[요약]{C.RESET} 탐지 CVE {total}개 중 "
          f"{C.GREEN}{len(mapped)}개{C.RESET} 에 익스플로잇 도구 매핑됨, "
          f"{C.GREY}{len(unmapped)}개{C.RESET} 미매핑")
    if os_hints:
        print(f"{C.BOLD}[OS 힌트]{C.RESET} {', '.join(os_hints)}")
    print(f"{C.DIM}[범위 뱃지] {C.RESET}{scope_badge('local')}{C.DIM} 단독 호스트 LPE   "
          f"{C.RESET}{scope_badge('both')}{C.DIM} 로컬/AD 모두   "
          f"{C.RESET}{scope_badge('domain')}{C.DIM} 도메인(AD) 환경에서만 사용 가능{C.RESET}")
    if ad_only:
        print(f"{C.RED}[주의]{C.RESET} 매핑된 {len(mapped)}개 중 {C.RED}{ad_only}개는 AD 전용{C.RESET}"
              f"{C.GREY} — 단독(standalone) 박스라면 사용 불가{C.RESET}")
    print()

    # 1) 도구가 매핑된 우선순위 CVE
    print(f"{C.GREEN}{C.BOLD}{'='*74}{C.RESET}")
    print(f"{C.GREEN}{C.BOLD} 우선순위: 익스플로잇 도구가 존재하는 CVE{C.RESET}")
    print(f"{C.GREEN}{C.BOLD}{'='*74}{C.RESET}")
    print(f"  {C.GREY}권장 순서: 서비스 오구성 · 권한남용(Potato) · 자격증명 먼저 시도 후 "
          f"{C.YELLOW}커널은 최후 수단{C.GREY}(BSOD/리셋 위험). 커널 항목은 하위 배치.{C.RESET}")
    if not mapped:
        print(f"  {C.GREY}매핑된 CVE 가 없습니다. 아래 권한 기반 기법을 확인하세요.{C.RESET}")
    for i, f in enumerate(mapped, 1):
        db = f["db"]
        aliases = db.get("aliases", [])
        alias_str = f" {C.YELLOW}({', '.join(aliases)}){C.RESET}" if aliases else ""
        badge = scope_badge(db.get("scope", "local"))
        kflag = f" {C.YELLOW}[커널·최후수단]{C.RESET}" if is_kernel(db) else ""
        print(f"\n{C.BOLD}[{i:>2}] {C.RED}{f['cve']}{C.RESET}{alias_str} {badge}{kflag}"
              f"  {C.DIM}{db.get('impact','')}{C.RESET}")
        print(f"     {C.DIM}{db.get('name','')}{C.RESET}")
        if db.get("os"):
            print(f"     {C.GREY}대상 OS: {db['os']}{C.RESET}")
        for t in db.get("tools", []):
            print(f"       {_tlabel(t.get('type',''))} {C.BOLD}{t['name']}{C.RESET}")
            print(f"            {C.BLUE}{t.get('url','')}{C.RESET}")
            if t.get("note"):
                print(f"            {C.GREY}> {t['note']}{C.RESET}")

    # 2) 권한 기반 (Potato 계열) - CVE 무관하게 항상 안내
    print(f"\n{C.MAGENTA}{C.BOLD}{'='*74}{C.RESET}")
    print(f"{C.MAGENTA}{C.BOLD} 권한 기반 기법: SeImpersonate/SeAssignPrimaryToken 보유 시 (Potato 계열){C.RESET}")
    print(f"{C.MAGENTA}{C.BOLD}{'='*74}{C.RESET}")
    print(f"  {C.GREY}먼저 확인: {C.RESET}{C.BOLD}whoami /priv{C.RESET}"
          f"{C.GREY}  ->  SeImpersonatePrivilege 가 Enabled 면 아래 도구가 강력함{C.RESET}")
    print(f"  {C.GREY}(IIS APPPOOL, mssql, 서비스 계정에서 자주 보유. CVE 없이도 SYSTEM 획득){C.RESET}")

    # 탐지된 OS 에 맞는 도구만 노출 (예: Server 2003 -> Churrasco 만, 최신 Potato 는 제외)
    hint_tok = os_tokens(" ".join(os_hints))
    if hint_tok:
        applicable = [t for t in potato_tools if os_tokens(t.get("os", "")) & hint_tok]
    else:
        applicable = list(potato_tools)
    if not applicable:            # 판정 불가 시 전체 노출 (숨김으로 인한 누락 방지)
        applicable = list(potato_tools)
    hidden = len(potato_tools) - len(applicable)

    for t in applicable:
        relevant = f" {C.GREEN}<- 탐지 OS 에 적합{C.RESET}" if hint_tok else ""
        print(f"\n     {_tlabel(t.get('type',''))} {C.BOLD}{t['name']}{C.RESET}{relevant}")
        print(f"          {C.GREY}적용: {t.get('os','')}{C.RESET}")
        print(f"          {C.BLUE}{t.get('url','')}{C.RESET}")
        if t.get("note"):
            print(f"          {C.GREY}> {t['note']}{C.RESET}")
    if hidden > 0:
        print(f"\n  {C.GREY}(탐지 OS 와 무관한 Potato 도구 {hidden}개는 숨김. "
              f"전체 목록은 exploit_db.json 참고){C.RESET}")

    # 3) 미매핑 CVE
    print(f"\n{C.GREY}{C.BOLD}{'='*74}{C.RESET}")
    print(f"{C.GREY}{C.BOLD} 도구 미매핑 CVE ({len(unmapped)}개){C.RESET}")
    print(f"{C.GREY}{C.BOLD}{'='*74}{C.RESET}")
    if show_all:
        for f in unmapped:
            exp = ""
            if f.get("exploit") and f["exploit"].lower() not in ("n/a", "", "none"):
                exp = f"  {C.YELLOW}[wes: {f['exploit']}]{C.RESET}"
            print(f"  {C.GREY}{f['cve']:<18}{C.RESET} {f.get('impact',''):<26} "
                  f"{C.DIM}{f.get('title','')[:40]}{C.RESET}{exp}")
    else:
        # wes.py 가 자체 exploit 링크를 단 것만 힌트로 노출
        with_exploit = [f for f in unmapped
                        if f.get("exploit") and f["exploit"].lower() not in ("n/a", "", "none")]
        for f in with_exploit[:15]:
            print(f"  {C.GREY}{f['cve']:<18}{C.RESET} {C.YELLOW}wes 자체 익스플로잇 링크 존재{C.RESET} "
                  f"{C.DIM}{f.get('title','')[:38]}{C.RESET}")
        if with_exploit:
            print(f"  {C.GREY}... 그 외 {len(unmapped)-min(len(with_exploit),15)}개는 "
                  f"--show-all 로 전체 확인{C.RESET}")
        else:
            print(f"  {C.GREY}--show-all 로 전체 {len(unmapped)}개 확인 가능{C.RESET}")

    print(f"\n{C.DIM}[안내] PETS 는 인가된 모의해킹/OSCP 실습용 참고 도구입니다. "
          f"익스플로잇 실행은 대상 권한을 확인하고 사용하세요.{C.RESET}\n")


def build_json(mapped, unmapped, os_hints, potato_tools):
    return {
        "os_hints": os_hints,
        "mapped": [
            {
                "cve": f["cve"],
                "impact": f.get("impact", ""),
                "severity": f.get("severity", ""),
                "scope": f["db"].get("scope", "local"),
                "aliases": f["db"].get("aliases", []),
                "name": f["db"].get("name", ""),
                "target_os": f["db"].get("os", ""),
                "tools": f["db"].get("tools", []),
                "refs": f["db"].get("refs", []),
            }
            for f in mapped
        ],
        "privilege_based_tools": potato_tools,
        "unmapped": [
            {"cve": f["cve"], "impact": f.get("impact", ""),
             "title": f.get("title", ""), "wes_exploit": f.get("exploit", "")}
            for f in unmapped
        ],
    }


# ===========================================================================
# AD 모드 (--ad): bloodhound-python JSON 을 읽어 권한상승 엣지 -> 도구 추천
# ===========================================================================

# BloodHound ACE RightName -> KB 엣지 키 (소문자 정규화 후 매칭)
RIGHT_ALIASES = {
    "genericall": "GenericAll",
    "genericwrite": "GenericWrite",
    "writedacl": "WriteDacl",
    "writeowner": "WriteOwner",
    "owns": "Owns", "owner": "Owns",
    "addmember": "AddMember", "addmembers": "AddMember", "addself": "AddMember",
    "forcechangepassword": "ForceChangePassword",
    "user-force-change-password": "ForceChangePassword",
    "allextendedrights": "AllExtendedRights",
    "addkeycredentiallink": "AddKeyCredentialLink",
    "readlapspassword": "ReadLAPSPassword",
    "readgmsapassword": "ReadGMSAPassword",
    "addallowedtoact": "AddAllowedToAct",
    "writespn": "WriteSPN", "addself-writespn": "WriteSPN",
    "gplink": "GpLink_GPO",
}
# GPO 대상 쓰기 엣지는 GPO 악용으로 재분류
GPO_WRITE_RIGHTS = {"GenericWrite", "GenericAll", "WriteDacl", "WriteOwner"}
# DCSync 판정용
DCSYNC_RIGHTS = {"getchanges", "getchangesall", "getchangesinfilteredset"}
# "누구나" 악용 가능한 저권한 주체 (우선순위 상향)
LOWPRIV_PRINCIPALS = ("DOMAIN USERS", "AUTHENTICATED USERS", "EVERYONE",
                      "DOMAIN COMPUTERS", "ANONYMOUS", "GUESTS", "USERS")


def load_ad_db(path=None):
    if path is None:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ad_edges.json")
    if not os.path.isfile(path):
        sys.exit(f"[!] AD 지식베이스를 찾을 수 없습니다: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _bh_type(obj, fname, meta):
    t = (meta.get("type") or "").lower()
    if t:
        return t
    for key in ("users", "groups", "computers", "domains", "gpos", "ous", "containers"):
        if key in os.path.basename(fname).lower():
            return key
    return "unknown"


def parse_bloodhound(json_path):
    """디렉터리(또는 단일 파일)에서 bloodhound-python JSON 을 읽어
    (sid_map, nodes) 반환. nodes 는 타입별 객체 리스트."""
    if os.path.isdir(json_path):
        files = [os.path.join(json_path, f) for f in os.listdir(json_path)
                 if f.lower().endswith(".json")]
    elif os.path.isfile(json_path):
        files = [json_path]
    else:
        sys.exit(f"[!] --json-path 경로를 찾을 수 없습니다: {json_path}")

    sid_map = {}
    nodes = {"users": [], "groups": [], "computers": [], "domains": [],
             "gpos": [], "ous": [], "containers": []}
    loaded = 0
    for fp in files:
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as f:
                doc = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(doc, dict) or "data" not in doc:
            continue
        meta = doc.get("meta", {}) if isinstance(doc.get("meta"), dict) else {}
        btype = _bh_type(doc, fp, meta)
        if btype not in nodes:
            continue
        for obj in doc.get("data", []):
            if not isinstance(obj, dict):
                continue
            props = obj.get("Properties", {}) or {}
            sid = obj.get("ObjectIdentifier") or props.get("objectid") or ""
            name = props.get("name") or props.get("distinguishedname") or sid
            if sid:
                sid_map[sid] = {"name": name, "type": btype[:-1] if btype.endswith("s") else btype}
            obj["_type"] = btype
            obj["_sid"] = sid
            obj["_name"] = name
            nodes[btype].append(obj)
        loaded += 1

    if loaded == 0:
        sys.exit("[!] --json-path 에서 유효한 BloodHound JSON 을 읽지 못했습니다.")
    return sid_map, nodes


def _resolve(sid, sid_map):
    info = sid_map.get(sid)
    if info:
        return info["name"]
    return sid or "(unknown)"


def analyze_ad(sid_map, nodes):
    """악용 가능한 엣지/속성을 수집. 반환: dict(edge_key -> list of finding)."""
    edges = {}   # edge_key -> [ {principal, principal_sid, target, target_type, lowpriv, inherited} ]
    props = {}   # prop_key -> [ {name, extra} ]

    def add_edge(key, principal_sid, target_name, target_type, inherited):
        pname = _resolve(principal_sid, sid_map)
        lowpriv = any(tok in pname.upper() for tok in LOWPRIV_PRINCIPALS)
        edges.setdefault(key, []).append({
            "principal": pname, "principal_sid": principal_sid,
            "target": target_name, "target_type": target_type,
            "lowpriv": lowpriv, "inherited": inherited,
        })

    def add_prop(key, name, extra=""):
        props.setdefault(key, []).append({"name": name, "extra": extra})

    all_objs = (nodes["users"] + nodes["groups"] + nodes["computers"] +
                nodes["domains"] + nodes["gpos"] + nodes["ous"] + nodes["containers"])

    # DCSync 누적 (principal_sid, domain_name) -> set(rights)
    dcsync_acc = {}

    for obj in all_objs:
        tname = obj.get("_name", "")
        ttype = obj.get("_type", "").rstrip("s")
        is_gpo = obj.get("_type") == "gpos"
        is_domain = obj.get("_type") == "domains"

        for ace in obj.get("Aces", []) or []:
            if not isinstance(ace, dict):
                continue
            raw = (ace.get("RightName") or "").strip()
            rl = raw.lower()
            psid = ace.get("PrincipalSID") or ace.get("PrincipalID") or ""
            inh = bool(ace.get("IsInherited"))

            # DCSync 조각 누적
            if rl in DCSYNC_RIGHTS and is_domain:
                dcsync_acc.setdefault((psid, tname), set()).add(rl)
                continue

            key = RIGHT_ALIASES.get(rl)
            if not key:
                continue
            # GPO 대상 쓰기 -> GPO 악용 엣지로 분류
            if is_gpo and key in GPO_WRITE_RIGHTS:
                key = "GpLink_GPO"
            add_edge(key, psid, tname, ttype, inh)

        # 위임 속성
        if obj.get("AllowedToDelegate"):
            add_prop("ConstrainedDelegation", tname,
                     "-> " + ", ".join(str(x) for x in obj["AllowedToDelegate"][:3]))
        if obj.get("HasSIDHistory"):
            add_prop("SIDHistory", tname)

        p = obj.get("Properties", {}) or {}
        if p.get("unconstraineddelegation"):
            add_prop("UnconstrainedDelegation", tname)
        if p.get("hasspn") and p.get("enabled", True) and not tname.upper().startswith("KRBTGT"):
            spns = p.get("serviceprincipalnames") or []
            add_prop("Kerberoastable", tname, (spns[0] if spns else ""))
        if p.get("dontreqpreauth"):
            add_prop("ASREPRoastable", tname)
        if p.get("passwordnotreqd"):
            add_prop("PasswordNotRequired", tname)

    # DCSync 확정 (GetChanges + GetChangesAll 동시 보유)
    for (psid, dom), rights in dcsync_acc.items():
        if {"getchanges", "getchangesall"} <= rights:
            pname = _resolve(psid, sid_map)
            lowpriv = any(tok in pname.upper() for tok in LOWPRIV_PRINCIPALS)
            edges.setdefault("DCSync", []).append({
                "principal": pname, "principal_sid": psid,
                "target": dom, "target_type": "domain",
                "lowpriv": lowpriv, "inherited": False,
            })

    return edges, props


def _edge_priority(ad_db, key):
    info = ad_db.get("edges", {}).get(key) or ad_db.get("properties", {}).get(key) or {}
    return {"high": 0, "med": 1, "low": 2}.get(info.get("priority", "med"), 1)


def print_ad_report(edges, props, ad_db, sid_map, nodes):
    print(f"{C.CYAN}{C.BOLD}{BANNER}{C.RESET}")
    nu, ng, nc = len(nodes["users"]), len(nodes["groups"]), len(nodes["computers"])
    n_edge = sum(len(v) for v in edges.values())
    n_prop = sum(len(v) for v in props.values())
    lowpriv_hits = sum(1 for v in edges.values() for e in v if e["lowpriv"])

    print(f"{C.BOLD}[AD 요약]{C.RESET} 노드: 사용자 {nu} · 그룹 {ng} · 컴퓨터 {nc}  |  "
          f"악용 엣지 {C.GREEN}{n_edge}건{C.RESET} ({len(edges)}종) · 속성 기반 {n_prop}건")
    if lowpriv_hits:
        print(f"{C.RED}[주의]{C.RESET} 저권한 주체(Domain Users 등)가 보유한 엣지 "
              f"{C.RED}{lowpriv_hits}건{C.RESET}{C.GREY} — 가장 먼저 확인하세요 (누구나 악용 가능){C.RESET}")
    print()

    edb = ad_db.get("edges", {})
    pdb = ad_db.get("properties", {})

    # 1) ACL 엣지 (우선순위 -> 저권한 주체 -> 건수)
    print(f"{C.GREEN}{C.BOLD}{'='*74}{C.RESET}")
    print(f"{C.GREEN}{C.BOLD} AD 권한상승 엣지 (BloodHound ACL/제어){C.RESET}")
    print(f"{C.GREEN}{C.BOLD}{'='*74}{C.RESET}")
    if not edges:
        print(f"  {C.GREY}악용 가능한 ACL 엣지를 찾지 못했습니다.{C.RESET}")
    for key in sorted(edges, key=lambda k: (_edge_priority(ad_db, k), -len(edges[k]))):
        info = edb.get(key, {})
        insts = edges[key]
        has_low = any(e["lowpriv"] for e in insts)
        low_tag = f" {C.RED}[저권한 주체 포함!]{C.RESET}" if has_low else ""
        print(f"\n{C.BOLD}● {C.RED}{key}{C.RESET} {C.DIM}({len(insts)}건){C.RESET}"
              f"  {C.YELLOW}{info.get('ko','')}{C.RESET}{low_tag}")
        if info.get("summary"):
            print(f"    {C.DIM}{info['summary']}{C.RESET}")
        # 구체 인스턴스 (저권한 주체 우선, 최대 6개)
        shown = sorted(insts, key=lambda e: (not e["lowpriv"], e["inherited"]))[:6]
        for e in shown:
            mark = f" {C.RED}<저권한>{C.RESET}" if e["lowpriv"] else ""
            inh = f" {C.GREY}(상속){C.RESET}" if e["inherited"] else ""
            print(f"      {C.CYAN}{e['principal']}{C.RESET} --{key}--> "
                  f"{C.BOLD}{e['target']}{C.RESET} {C.GREY}[{e['target_type']}]{C.RESET}{mark}{inh}")
        if len(insts) > len(shown):
            print(f"      {C.GREY}... 그 외 {len(insts)-len(shown)}건{C.RESET}")
        # 악용 방법
        for ab in info.get("abuse", []):
            print(f"      {C.MAGENTA}▸ {ab.get('when','')}{C.RESET}")
            for cmd in ab.get("cmd", []):
                print(f"        {C.GREEN}$ {cmd}{C.RESET}" if not cmd.startswith("#")
                      else f"        {C.GREY}{cmd}{C.RESET}")
        for t in info.get("tools", []):
            print(f"        {_tlabel(t.get('type',''))} {t['name']}  {C.BLUE}{t.get('url','')}{C.RESET}")

    # 2) 속성 기반 (Kerberoast / AS-REP / 위임 등)
    print(f"\n{C.MAGENTA}{C.BOLD}{'='*74}{C.RESET}")
    print(f"{C.MAGENTA}{C.BOLD} 속성 기반 공격 (Roast / 위임 / 기타){C.RESET}")
    print(f"{C.MAGENTA}{C.BOLD}{'='*74}{C.RESET}")
    if not props:
        print(f"  {C.GREY}속성 기반 대상이 없습니다.{C.RESET}")
    for key in sorted(props, key=lambda k: _edge_priority(ad_db, k)):
        info = pdb.get(key, {})
        insts = props[key]
        print(f"\n{C.BOLD}● {C.RED}{key}{C.RESET} {C.DIM}({len(insts)}건){C.RESET}"
              f"  {C.YELLOW}{info.get('ko','')}{C.RESET}")
        if info.get("summary"):
            print(f"    {C.DIM}{info['summary']}{C.RESET}")
        for e in insts[:8]:
            extra = f" {C.GREY}{e['extra']}{C.RESET}" if e.get("extra") else ""
            print(f"      {C.BOLD}{e['name']}{C.RESET}{extra}")
        if len(insts) > 8:
            print(f"      {C.GREY}... 그 외 {len(insts)-8}건{C.RESET}")
        for cmd in info.get("cmd", []):
            print(f"        {C.GREEN}$ {cmd}{C.RESET}" if not cmd.startswith("#")
                  else f"        {C.GREY}{cmd}{C.RESET}")
        for t in info.get("tools", []):
            print(f"        {_tlabel(t.get('type',''))} {t['name']}  {C.BLUE}{t.get('url','')}{C.RESET}")

    print(f"\n{C.DIM}[안내] PETS AD 모드는 인가된 모의해킹/실습용입니다. "
          f"비번 리셋 등은 운영 계정 잠금 위험이 있으니 대상 권한을 확인하고 사용하세요.{C.RESET}\n")


def build_ad_json(edges, props):
    return {
        "edges": {k: v for k, v in edges.items()},
        "properties": {k: v for k, v in props.items()},
    }


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def _run_ad(args):
    ad_db = load_ad_db(args.ad_db)
    sid_map, nodes = parse_bloodhound(args.json_path)
    edges, props = analyze_ad(sid_map, nodes)
    print_ad_report(edges, props, ad_db, sid_map, nodes)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(build_ad_json(edges, props), f, ensure_ascii=False, indent=2)
        print(f"[+] JSON 결과 저장: {args.json}")


def main():
    ap = argparse.ArgumentParser(
        description="PETS - wes.py CVE 를 실제 익스플로잇 도구로 매핑/추천",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("wes_output", nargs="?", help="wes.py 출력 파일 (텍스트 또는 CSV)")
    ap.add_argument("--ad", action="store_true",
                    help="AD 모드: BloodHound(bloodhound-python) JSON 을 분석")
    ap.add_argument("--json-path", dest="json_path",
                    help="[--ad 필수] bloodhound-python JSON 들이 있는 디렉터리(또는 단일 파일)")
    ap.add_argument("--db", help="지식베이스 JSON 경로 (기본: 스크립트 옆 exploit_db.json)")
    ap.add_argument("--ad-db", dest="ad_db",
                    help="AD 지식베이스 경로 (기본: 스크립트 옆 ad_edges.json)")
    ap.add_argument("--show-all", action="store_true", help="미매핑 CVE 전체 표시")
    ap.add_argument("--json", metavar="FILE", help="결과를 JSON 으로 저장")
    ap.add_argument("--no-color", action="store_true", help="색상 출력 끄기")
    args = ap.parse_args()

    if args.no_color or not sys.stdout.isatty():
        C.disable()
        # 라벨 재계산
        global TYPE_LABEL
        TYPE_LABEL = {k: f"[{k.upper()[:3]:<3}]" for k in TYPE_LABEL}

    # AD 모드 분기
    if args.ad:
        if not args.json_path:
            sys.exit("[!] --ad 모드에는 --json-path <BloodHound JSON 디렉터리> 가 필요합니다.")
        _run_ad(args)
        return

    if not args.wes_output:
        sys.exit("[!] wes.py 출력 파일을 지정하거나, AD 분석은 --ad --json-path 를 사용하세요.")
    if not os.path.isfile(args.wes_output):
        sys.exit(f"[!] 입력 파일을 찾을 수 없습니다: {args.wes_output}")

    db = load_db(args.db)
    findings_raw = parse_wes(args.wes_output)
    if not findings_raw:
        sys.exit("[!] wes.py 출력에서 CVE 를 찾지 못했습니다. 파일 형식을 확인하세요.")

    with open(args.wes_output, "r", encoding="utf-8", errors="replace") as f:
        full_text = f.read()

    findings = dedupe(findings_raw)
    os_hints = detect_os(findings, full_text)
    mapped, unmapped = map_findings(findings, db)
    potato_tools = db.get("privilege_based_tools", [])

    print_report(mapped, unmapped, os_hints, potato_tools, args.show_all)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(build_json(mapped, unmapped, os_hints, potato_tools),
                      f, ensure_ascii=False, indent=2)
        print(f"[+] JSON 결과 저장: {args.json}")


if __name__ == "__main__":
    main()
