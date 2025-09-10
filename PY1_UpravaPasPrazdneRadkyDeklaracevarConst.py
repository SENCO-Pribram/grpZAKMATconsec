# -*- coding: utf-8 -*-
import os
import re
import sys
import argparse

# ---------------------------------------
# NASTAVENÍ
# ---------------------------------------
KEYWORDS = [
    "unit", "interface", "uses", "type", "const", "resourcestring",
    "private", "public", "published", "strict private", "strict protected",
    "var", "implementation", "initialization", "finalization", "{$R *.dfm}"
]

EXCLUDE_DIRS = {"__history", "win32", "win64", "thirdparty", "venv", ".git", ".svn", ".hg", ".idea", ".vs"}

# ---------------------------------------
# REGEXY
# ---------------------------------------
RE_USES_INLINE = re.compile(r"^\s*uses\s+(.+?);\s*(//.*)?$", re.IGNORECASE)
RE_USES_ALONE  = re.compile(r"^\s*uses\b\s*$", re.IGNORECASE)

KEYWORDS_SORTED = sorted(KEYWORDS, key=len, reverse=True)
RE_BLOCK_START = re.compile(
    r"^\s*(?:" + "|".join(re.escape(k) for k in KEYWORDS_SORTED) + r")\b",
    re.IGNORECASE
)

# začátek hlavičky rutiny (na sloupci 1), hlavička může být vícerádková
RE_ROUTINE_HDR_COL1 = re.compile(
    r"^(?:class\s+)?(?:procedure|function|constructor|destructor|operator)\b",
    re.IGNORECASE
)

RE_ATTR_LINE = re.compile(r"^\s*\[.*\]\s*$")      # atributy nad hlavičkou
RE_END_SEMI   = re.compile(r"\bend\s*;", re.IGNORECASE)

RE_BEGIN = re.compile(r"^\s*begin\b", re.IGNORECASE)   # begin (lib. odsazení)
RE_BEGIN_COL1 = re.compile(r"^begin\b", re.IGNORECASE) # begin na sloupci 1

# lokální sekce, které mohou následovat hned po hlavičce rutiny
LOCAL_SECTION_COL1 = re.compile(r"^(?:var|const|type|label|begin)\b", re.IGNORECASE)
LOCAL_VAR_CONST_COL1 = re.compile(r"^(?:var|const)\b", re.IGNORECASE)

# ---------------------------------------
# I/O
# ---------------------------------------
def read_text(path):
    with open(path, "rb") as f:
        raw = f.read()
    for enc in ("utf-8-sig", "utf-8", "cp1250", "cp1252"):
        try:
            return raw.decode(enc), enc
        except UnicodeDecodeError:
            pass
    return raw.decode("utf-8", errors="replace"), "fallback"

def write_text(path, text):
    # Zapisujme jako UTF-8 s BOM
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        f.write(text)

# ---------------------------------------
# Pomocné funkce
# ---------------------------------------
def is_blank(s: str) -> bool:
    return s.strip() == ""

def strip_line_comment(s: str) -> str:
    idx = s.find("//")
    return s if idx < 0 else s[:idx]

def strip_strings_and_line_comments(s: str) -> str:
    s = strip_line_comment(s)
    return re.sub(r"'(?:''|[^'])*'", "", s)

def last_nonblank_index(buf) -> int:
    for j in range(len(buf) - 1, -1, -1):
        if not is_blank(buf[j]):
            return j
    return -1

def count_block_deltas(code_line: str):
    s = strip_strings_and_line_comments(code_line).lower()
    up = s.count("begin") + s.count("try") + s.count("case") + s.count("asm")
    down = s.count("end")
    has_end_semi = "end;" in s
    return up - down, has_end_semi

def paren_delta(code_line: str) -> int:
    s = strip_strings_and_line_comments(code_line)
    return s.count("(") - s.count(")")

def line_has_term_semicolon(code_line: str, depth: int) -> bool:
    s = strip_strings_and_line_comments(code_line)
    return depth == 0 and ";" in s

# ---------------------------------------
# Hlavní transformace
# ---------------------------------------
def fix_text(text: str) -> str:
    lines = text.splitlines(keepends=False)
    new = []
    i = 0
    in_impl = False

    # Stav pro oddělování top-level rutin
    in_top_routine = False
    routine_depth = 0

    # Jsme bezprostředně po *celé* hlavičce rutiny?
    after_hdr = False

    # Jsme uvnitř lokální deklarace (po top-level var/const v rutině) – až do begin?
    in_local_decl = False

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # --- Pokud jsme po hlavičce, nejdřív řeš „žádný blank před var/const/type/label/begin“
        if in_impl and after_hdr:
            # zahodit prázdné řádky bezprostředně za hlavičkou
            if is_blank(line):
                i += 1
                continue

            # první obsah: pokud je to top-level var/const, zapneme režim lokálních deklarací
            if not line.startswith((" ", "\t")) and LOCAL_VAR_CONST_COL1.match(stripped):
                new.append(line)         # 'var' nebo 'const' zůstává na sloupci 1
                after_hdr = False
                in_local_decl = True     # od teď vynucujeme odsazení 2 mezery až do 'begin'
                i += 1
                continue

            # pokud je to jiný top-level obsah (type/label/begin/kód), přidej bez mezery
            new.append(line)
            after_hdr = False

            # update hloubky v rutině
            if in_top_routine:
                delta, has_end = count_block_deltas(line)
                prev = routine_depth
                routine_depth += delta
                if has_end and routine_depth == 0 and prev >= 0:
                    if new and not is_blank(new[-1]):
                        new.append("")
                    in_top_routine = False
            i += 1
            continue

        # --- Režim lokálních deklarací (po var/const) – až do begin na sloupci 1
        if in_impl and in_local_decl:
            # Konec režimu: 'begin' na sloupci 1
            if not line.startswith((" ", "\t")) and RE_BEGIN_COL1.match(stripped):
                new.append(line)
                in_local_decl = False
                i += 1
                continue

            # Nový lokální 'var'/'const' na sloupci 1 – nezačíná blok, ale přepne sekci, režim trvá
            if not line.startswith((" ", "\t")) and LOCAL_VAR_CONST_COL1.match(stripped):
                new.append(line)  # ponecháme na sloupci 1
                i += 1
                continue

            # Ostatní řádky mezi var/const a begin:
            if is_blank(line):
                new.append(line)  # prázdný řádek zachováme
            else:
                # Přepiš libovolné počáteční whitespace na přesně dvě mezery
                new.append(re.sub(r"^\s*", "  ", line))
            i += 1
            continue

        # --- Inline uses
        m = RE_USES_INLINE.match(line)
        if m:
            units = m.group(1).strip()
            if new and not is_blank(new[-1]):
                new.append("")
            new.append("uses")
            new.append("  " + units + ";")
            nxt = lines[i + 1].strip() if i + 1 < len(lines) else ""
            if nxt and not RE_BLOCK_START.match(nxt):
                new.append("")
            i += 1
            continue

        # --- Vícerádkové uses začínající samotným "uses"
        if RE_USES_ALONE.match(line):
            if new and not is_blank(new[-1]):
                new.append("")
            new.append("uses")
            i += 1
            while i < len(lines):
                new.append(lines[i])
                semiline = strip_line_comment(lines[i])
                if ";" in semiline:
                    nxt = lines[i + 1].strip() if i + 1 < len(lines) else ""
                    if nxt:
                        new.append("")
                    break
                i += 1
            i += 1
            continue

        # --- Začátky globálních bloků/klíčových slov
        if RE_BLOCK_START.match(stripped):
            kw = stripped.split()[0].lower()

            if kw == "implementation":
                in_impl = True
                in_top_routine = False
                routine_depth = 0
                after_hdr = False
                in_local_decl = False

            is_top_level_block = not line.startswith((" ", "\t"))

            if is_top_level_block:
                if new and not is_blank(new[-1]):
                    new.append("")
                new.append(line)
                if kw == "implementation":
                    if not (i + 1 < len(lines) and is_blank(lines[i + 1])):
                        new.append("")
            else:
                new.append(line)

            i += 1
            continue

        # --- ZAČÁTEK HLAVIČKY TOP-LEVEL RUTINY (může být vícerádková)
        if in_impl and not line.startswith((" ", "\t")) and RE_ROUTINE_HDR_COL1.match(stripped):
            # 1) Zajistit 1 prázdný řádek PŘED (s ohledem na atributy)
            while new and is_blank(new[-1]):
                new.pop()

            j = len(new) - 1
            while j >= 0 and RE_ATTR_LINE.match(new[j]):
                j -= 1

            last_idx = j
            while last_idx >= 0 and is_blank(new[last_idx]):
                last_idx -= 1

            need_blank = not (last_idx >= 0 and new[last_idx].strip().lower() == "implementation")
            if need_blank:
                insert_pos = j + 1
                new[insert_pos:insert_pos] = [""]

            # 2) Nasaj CELÝ blok hlavičky až po terminující ';' mimo závorky
            paren_depth = 0
            while True:
                new.append(line)
                paren_depth += paren_delta(line)
                if line_has_term_semicolon(line, paren_depth):
                    break
                i += 1
                if i >= len(lines):
                    break
                line = lines[i]

            # 3) Nastav stavy: jsme v rutině, a jsme „po hlavičce“
            in_top_routine = True
            routine_depth = 0
            after_hdr = True
            in_local_decl = False

            i += 1
            continue

        # --- Ostatní řádky
        new.append(line)

        # udrž 1 prázdný řádek po ukončení top-level rutiny
        if in_impl and in_top_routine:
            delta, has_end = count_block_deltas(line)
            prev = routine_depth
            routine_depth += delta
            if has_end and routine_depth == 0 and prev >= 0:
                if new and not is_blank(new[-1]):
                    new.append("")
                in_top_routine = False
                in_local_decl = False
                after_hdr = False

        i += 1

    # Normalizace: max 1 prázdný řádek po sobě a 1 EOL na konci
    compact = []
    for s in new:
        if not (s == "" and compact and compact[-1] == ""):
            compact.append(s)
    result = "\n".join(compact).rstrip() + "\n"
    return result

# ---------------------------------------
# Zpracování souboru
# ---------------------------------------
def process_file(path: str):
    original, enc = read_text(path)
    fixed = fix_text(original)
    if fixed != original:
        write_text(path, fixed)
        print("Úprava souboru:", path)

# ---------------------------------------
# Projití adresáře / CLI
# ---------------------------------------
def process_path(base_path: str):
    changed = 0
    if os.path.isfile(base_path):
        if base_path.lower().endswith(".pas"):
            process_file(base_path)
            changed += 1
        else:
            print("Soubor ignorován (není .pas):", base_path)
        return changed

    for root, dirs, files in os.walk(base_path):
        # odfiltruj nechtěné složky
        dirs[:] = [d for d in dirs if d.lower() not in EXCLUDE_DIRS]
        for name in files:
            if name.lower().endswith(".pas"):
                full = os.path.join(root, name)
                process_file(full)
                changed += 1
    return changed

def parse_args():
    ap = argparse.ArgumentParser(
        description="Úprava Pascal (*.pas) souborů: uses/oddíly/hlavičky. Ukládá jako UTF-8 s BOM."
    )
    ap.add_argument(
        "path",
        nargs="?",
        help="Cesta k .pas souboru nebo složce. Pokud se nezadá, použije se adresář se skriptem.",
    )
    return ap.parse_args()

if __name__ == "__main__":
    args = parse_args()
    if args.path:
        base = os.path.abspath(args.path)
    else:
        # adresář, kde leží tento skript
        base = os.path.dirname(os.path.abspath(__file__))

    if not os.path.exists(base):
        print("Cesta neexistuje:", base, file=sys.stderr)
        sys.exit(2)

    total = process_path(base)
    print("Hotovo. Vše uloženo jako UTF-8 s BOM. Zpracováno souborů:", total)
