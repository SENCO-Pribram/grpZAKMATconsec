# delphi_formatter.py
# -*- coding: utf-8 -*-
"""
Delphi .pas formatter (mezery a odsazení ve stylu Delphi)
- Bezpečně maskuje řetězce a komentáře -> formátování běží jen na kódu
- Sjednocuje mezery kolem :=, =, +, -, čárek, středníků a závorek
- Odsazuje podle begin/end, try/except/finally, case a po then/do (bez begin)
- Režim: soubor nebo rekurzivně složka (spuštěno bez cesty -> adresář se skriptem)
- I/O: čte v ('utf-8-sig','utf-8','cp1250','cp1252'), zapisuje jako UTF-8 s BOM

Použití:
    python delphi_formatter.py                # projde adresář se skriptem
    python delphi_formatter.py PATH           # projde zadaný soubor/složku
    python delphi_formatter.py PATH --dry-run # jen ukáže změny
    python delphi_formatter.py PATH --indent 2
"""

import os
import re
import sys
import argparse
from typing import List, Tuple

# ---------- I/O s ohledem na UTF-8 s BOM ----------

def read_text(path: str):
    with open(path, "rb") as f:
        raw = f.read()
    for enc in ("utf-8-sig", "utf-8", "cp1250", "cp1252"):
        try:
            return raw.decode(enc), enc
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace"), "fallback"

def write_text(path: str, text: str):
    # Zapisujeme JEDNOTNĚ jako UTF-8 s BOM
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        f.write(text)

# ---------- Maskování řetězců/komentářů ----------

PLACEHOLDER_STR = "\uE000STR{}"   # Private Use Area, minimální kolize
PLACEHOLDER_CMT = "\uE100CMT{}"

def extract_strings_and_comments(text: str) -> Tuple[str, List[str], List[str]]:
    """
    Nahradí řetězce a komentáře placeholdery a vrátí:
    - text s placeholdery
    - list řetězců (uložené jsou bez počátečního apostrofu, ale včetně koncového)
    - list komentářů (uložené VČETNĚ značek //, {...}, (*...*))
    Podporuje: '...'(s escapem ''), //..., {...}, (*...*)
    """
    i = 0
    n = len(text)
    out = []
    strings: List[str] = []
    comments: List[str] = []

    in_str = False
    in_cmt_line = False
    in_cmt_brace = False
    in_cmt_paren = False

    while i < n:
        ch = text[i]
        ch2 = text[i:i+2]

        # --- uvnitř řádkového komentáře // ---
        if in_cmt_line:
            j = i
            while j < n and text[j] != '\n':
                j += 1
            comments.append('//' + text[i:j])  # ulož včetně //
            out.append(PLACEHOLDER_CMT.format(len(comments)-1))
            i = j
            in_cmt_line = False
            continue

        # --- uvnitř { ... } ---
        if in_cmt_brace:
            j = i
            while j < n and text[j] != '}':
                j += 1
            if j < n:
                j += 1  # zahrň '}'
            comments.append('{' + text[i:j])  # ulož včetně { }
            out.append(PLACEHOLDER_CMT.format(len(comments)-1))
            i = j
            in_cmt_brace = False
            continue

        # --- uvnitř (* ... *) ---
        if in_cmt_paren:
            j = i
            while j < n-1 and text[j:j+2] != '*)':
                j += 1
            if j < n-1:
                j += 2  # zahrň '*)'
            comments.append('(*' + text[i:j])  # ulož včetně (* *)
            out.append(PLACEHOLDER_CMT.format(len(comments)-1))
            i = j
            in_cmt_paren = False
            continue

        # --- uvnitř řetězce '...' (s podporou '') ---
        if in_str:
            j = i
            while j < n:
                if text[j] == "'":
                    if j+1 < n and text[j+1] == "'":
                        j += 2  # escapovaný apostrof
                        continue
                    else:
                        j += 1  # zahrň koncový apostrof
                        break
                j += 1
            strings.append(text[i:j])  # obsah + koncový '
            out.append(PLACEHOLDER_STR.format(len(strings)-1))
            i = j
            in_str = False
            continue

        # --- detekce začátků řetězců/komentářů ---
        if ch == "'":
            in_str = True
            i += 1
            continue
        if ch2 == '//':
            in_cmt_line = True
            i += 2
            continue
        if ch == '{':
            in_cmt_brace = True
            i += 1
            continue
        if ch2 == '(*':
            in_cmt_paren = True
            i += 2
            continue

        # běžný znak
        out.append(ch)
        i += 1

    return ''.join(out), strings, comments

def restore_placeholders(text: str, strings: List[str], comments: List[str]) -> str:
    def repl_str(m):
        idx = int(m.group(1))
        val = strings[idx]
        # strings[idx] neobsahuje počáteční apostrof -> doplníme
        return "'" + val if not val.startswith("'") else val

    def repl_cmt(m):
        idx = int(m.group(1))
        return comments[idx]  # uloženo včetně značek

    text = re.sub(r'\uE000STR(\d+)', repl_str, text)
    text = re.sub(r'\uE100CMT(\d+)', repl_cmt, text)
    return text

# ---------- Pravidla mezer ----------

def fix_commas_and_parens(s: str) -> str:
    # čárky: žádná mezera před, jedna mezera po
    s = re.sub(r'\s+,', ',', s)
    s = re.sub(r',\s*', ', ', s)
    # závorky: žádná mezera po '(' a před ')'
    s = re.sub(r'\(\s+', '(', s)
    s = re.sub(r'\s+\)', ')', s)
    # volání funkcí: žádná mezera před '('
    s = re.sub(r'([A-Za-z_]\w*)\s+\(', r'\1(', s)
    return s

def fix_colons(s: str) -> str:
    # ':' s mezerou po (typové deklarace), ale ne pro ':='
    s = re.sub(r'\s*:(?!=)\s*', ': ', s)
    # ':=' vždy s mezerami okolo
    s = re.sub(r'\s*:=\s*', ' := ', s)
    return s

def space_binary_ops(s: str) -> str:
    # vícesymbolové jako první
    s = re.sub(r'\s*<=\s*', ' <= ', s)
    s = re.sub(r'\s*>=\s*', ' >= ', s)
    s = re.sub(r'\s*<>\s*', ' <> ', s)
    # '=' (ne součást ':=')
    s = re.sub(r'(?<!:)\s*=\s*(?!\=)', ' = ', s)
    # '*' a '/' jsou vždy binární
    s = re.sub(r'\s*\*\s*', ' * ', s)
    s = re.sub(r'\s*/\s*', ' / ', s)
    # '+' a '-' – ponech unární, přidej mezery jen když jsou binární (mezi tokeny)
    s = re.sub(r'(?<=\w|\))\s*\+\s*(?=\w|\()', ' + ', s)
    s = re.sub(r'(?<=\w|\))\s*-\s*(?=\w|\()', ' - ', s)
    # samostatné < a >
    s = re.sub(r'(?<![<>=])\s<\s(?![<>=])', ' < ', s)
    s = re.sub(r'(?<![<>=])\s>\s(?![<>=])', ' > ', s)
    return s

def fix_semicolons(s: str) -> str:
    # žádná mezera před ';'
    s = re.sub(r'\s+;', ';', s)
    return s

def apply_spacing_rules(code: str) -> str:
    code = fix_commas_and_parens(code)
    code = fix_colons(code)
    code = space_binary_ops(code)
    code = fix_semicolons(code)
    # 'then' / 'do' – sjednotit 1 mezeru před
    code = re.sub(r'\s*then\b', ' then', code, flags=re.IGNORECASE)
    code = re.sub(r'\s*do\b', ' do', code, flags=re.IGNORECASE)
    # odstraň trailing spaces
    code = re.sub(r'[ \t]+\r?\n', '\n', code)
    return code

# ---------- Odsazení ----------

BEGIN_INC_RE = re.compile(r'\b(begin|try|case|record|class|object)\b', re.IGNORECASE)
THEN_DO_RE   = re.compile(r'\b(then|do)\b', re.IGNORECASE)

def line_starts_dedent(core: str) -> bool:
    return re.match(r'^(end|until|else|except|finally)\b', core, flags=re.IGNORECASE) is not None

def line_increases_after(core: str) -> bool:
    if BEGIN_INC_RE.search(core):
        return True
    # zvýšení po 'then'/'do', pokud na řádku není 'begin'
    if THEN_DO_RE.search(core) and not re.search(r'\bbegin\b', core, flags=re.IGNORECASE):
        return True
    # 'else'/'except'/'finally' typicky zahájí blok následujícím řádkem
    if re.match(r'^(else|except|finally)\b', core, flags=re.IGNORECASE):
        return True
    return False

LABEL_RE = re.compile(r'^\s*([A-Za-z_]\w*\s*:\s*)')

def indent_code(text: str, indent: int = 2) -> str:
    lines = text.splitlines()
    level = 0
    out_lines = []

    for raw in lines:
        line = raw.rstrip()
        if line.strip() == '':
            out_lines.append('')
            continue

        # zachovej volitelné labely na sloupci 1
        label_match = LABEL_RE.match(line)
        label = ''
        rest = line
        if label_match:
            label = label_match.group(1)
            rest = line[label_match.end():]

        core = rest.lstrip()

        # dedent dříve, pokud řádek začíná koncovým slovem
        if line_starts_dedent(core):
            level = max(level - 1, 0)

        indent_str = ' ' * (indent * level)
        out_lines.append(f"{label}{indent_str}{core}")

        # zvýšení úrovně po aktuálním řádku?
        if line_increases_after(core):
            level += 1

    return '\n'.join(out_lines) + '\n'

# ---------- Hlavní formatter ----------

def format_delphi_pas(text: str, indent: int = 2) -> str:
    # 1) maskování
    masked, strings, comments = extract_strings_and_comments(text)
    # 2) mezery
    masked = apply_spacing_rules(masked)
    # 3) odsazení
    masked = indent_code(masked, indent=indent)
    # 4) návrat stringů/komentářů
    final = restore_placeholders(masked, strings, comments)
    # finální úklid: trailing spaces na koncích řádků
    final = re.sub(r'[ \t]+\r?\n', '\n', final)
    return final

# ---------- Zpracování souborů/složek ----------

EXCLUDE_DIRS = {"__history", "win32", "win64", "thirdparty", "venv", ".git", ".svn", ".hg", ".idea", ".vs"}

def process_file(path: str, indent: int, dry_run: bool = False) -> bool:
    original, enc = read_text(path)
    formatted = format_delphi_pas(original, indent=indent)
    if formatted != original:
        if dry_run:
            print(f"[DRY] Změna: {path} (detekováno {enc} -> zapisoval bych UTF-8 s BOM)")
        else:
            write_text(path, formatted)
            print(f"Upraveno: {path} (detekováno {enc}, uloženo jako UTF-8 s BOM)")
        return True
    else:
        print(f"OK     : {path} (bez změny)")
        return False

def process_path(path: str, indent: int, dry_run: bool = False) -> int:
    changed = 0
    if os.path.isfile(path):
        if path.lower().endswith(".pas"):
            changed += 1 if process_file(path, indent, dry_run) else 0
        else:
            print(f"Soubor ignorován (není .pas): {path}")
        return changed

    # složka
    for root, dirs, files in os.walk(path):
        # filtr složek
        dirs[:] = [d for d in dirs if d.lower() not in EXCLUDE_DIRS]
        for name in files:
            if name.lower().endswith(".pas"):
                full = os.path.join(root, name)
                changed += 1 if process_file(full, indent, dry_run) else 0
    return changed

# ---------- CLI ----------

def parse_args():
    ap = argparse.ArgumentParser(
        description="Delphi .pas formatter (mezery + odsazení). Zapisuje jako UTF-8 s BOM."
    )
    ap.add_argument(
        "path",
        nargs="?",
        help="Cesta k .pas souboru nebo složce (pokud se nezadá, použije se adresář se skriptem)",
    )
    ap.add_argument("--indent", type=int, default=2,
                    help="Počet mezer pro jeden stupeň odsazení (výchozí 2)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Jen vypsat soubory, které by se změnily (nic neukládat)")
    return ap.parse_args()

def main():
    args = parse_args()

    if args.path:
        base_path = os.path.abspath(args.path)
    else:
        # adresář, kde leží tento skript
        base_path = os.path.dirname(os.path.abspath(__file__))

    if not os.path.exists(base_path):
        print(f"Cesta neexistuje: {base_path}", file=sys.stderr)
        sys.exit(2)

    changed = process_path(base_path, indent=args.indent, dry_run=args.dry_run)

    if args.dry_run:
        print(f"\nDRY-RUN hotovo. Změnilo by se {changed} souborů.")
    else:
        print(f"\nHotovo. Upraveno {changed} souborů. Vše uloženo jako UTF-8 s BOM.")

if __name__ == "__main__":
    main()
