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
        return (-(impact_score(f) + tool_bonus), f["cve"])

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


def print_report(mapped, unmapped, os_hints, potato_tools, show_all):
    print(f"{C.CYAN}{C.BOLD}{BANNER}{C.RESET}")

    total = len(mapped) + len(unmapped)
    print(f"{C.BOLD}[요약]{C.RESET} 탐지 CVE {total}개 중 "
          f"{C.GREEN}{len(mapped)}개{C.RESET} 에 익스플로잇 도구 매핑됨, "
          f"{C.GREY}{len(unmapped)}개{C.RESET} 미매핑")
    if os_hints:
        print(f"{C.BOLD}[OS 힌트]{C.RESET} {', '.join(os_hints)}")
    print()

    # 1) 도구가 매핑된 우선순위 CVE
    print(f"{C.GREEN}{C.BOLD}{'='*74}{C.RESET}")
    print(f"{C.GREEN}{C.BOLD} 우선순위: 익스플로잇 도구가 존재하는 CVE{C.RESET}")
    print(f"{C.GREEN}{C.BOLD}{'='*74}{C.RESET}")
    if not mapped:
        print(f"  {C.GREY}매핑된 CVE 가 없습니다. 아래 권한 기반 기법을 확인하세요.{C.RESET}")
    for i, f in enumerate(mapped, 1):
        db = f["db"]
        aliases = db.get("aliases", [])
        alias_str = f" {C.YELLOW}({', '.join(aliases)}){C.RESET}" if aliases else ""
        print(f"\n{C.BOLD}[{i:>2}] {C.RED}{f['cve']}{C.RESET}{alias_str}"
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


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="PETS - wes.py CVE 를 실제 익스플로잇 도구로 매핑/추천",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("wes_output", help="wes.py 출력 파일 (텍스트 또는 CSV)")
    ap.add_argument("--db", help="지식베이스 JSON 경로 (기본: 스크립트 옆 exploit_db.json)")
    ap.add_argument("--show-all", action="store_true", help="미매핑 CVE 전체 표시")
    ap.add_argument("--json", metavar="FILE", help="결과를 JSON 으로 저장")
    ap.add_argument("--no-color", action="store_true", help="색상 출력 끄기")
    args = ap.parse_args()

    if args.no_color or not sys.stdout.isatty():
        C.disable()
        # 라벨 재계산
        global TYPE_LABEL
        TYPE_LABEL = {k: f"[{k.upper()[:3]:<3}]" for k in TYPE_LABEL}

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
