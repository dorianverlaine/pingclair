#!/usr/bin/env python3
"""📚 用上游自己的 Caddyfile 語料量覆蓋率，並凍結 baseline。

語料來源是上游倉庫的 `caddytest/integration/caddyfile_adapt/*.caddyfiletest`：
234 個檔，每個是「一份設定 ＋ `----------` ＋ 預期 JSON」，由那個專案自己的
維護者維護。

**為什麼用它而不是自己寫案例**：我們自己寫的案例反映的是「我們以為 Caddyfile
長什麼樣」。這份語料反映的是它**實際**長什麼樣，包含我們根本沒想到要測的形狀。
2026-08-05 已經證明過一次：黑箱 60 個案例量到 11 個缺失指令，讀註冊表一次拿到 26 個。

**這份 harness 只量「編不編得過」**，刻意不比對預期 JSON——那份 JSON 是上游的
schema（`apps.http.servers.…`），我們的 `adapt` 是我們自己的 schema，逐位元比
沒有意義。行為對照走 `compare.py`，而且只有能在本機起服務的子集適用。

輸出兩份：
  baseline.json  機器讀，之後每次重構跟它 diff
  CORPUS.md      人讀，失敗按原因分類並排序
"""

import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

CORPUS_DIR = Path(
    os.environ.get(
        "PC_CORPUS",
        "/Users/sinclairverlaine/code/caddy/caddytest/integration/caddyfile_adapt",
    )
)
BASE = Path(os.environ.get("PC_BASE", Path(__file__).resolve().parent))
BIN = Path(os.environ.get("PC_BIN", BASE / "pingclair"))
OUT = Path(os.environ.get("PC_EVIDENCE", BASE / "evidence"))
OUT.mkdir(parents=True, exist_ok=True)
WORK = Path("/tmp/corpus")
WORK.mkdir(exist_ok=True)

# 🧭 The corpus imports files by paths relative to the configuration, and those
# paths point at a `testdata/` directory that sits one level above the fixtures.
# Our `import` resolves against the importing file's own directory, so a case
# copied into a scratch directory could never find them — and the failures
# looked like ours. Link the directory in instead of writing into someone
# else's checkout.
_TESTDATA = CORPUS_DIR.parent / "testdata"
_LINK = WORK / "testdata"
if _TESTDATA.is_dir() and not _LINK.exists():
    try:
        _LINK.symlink_to(_TESTDATA, target_is_directory=True)
    except OSError:
        pass

SEPARATOR = re.compile(r"^-{5,}$", re.M)


def split_fixture(text):
    """✂️ 拆成（設定, 預期輸出是不是 JSON）。

    語料裡有 27 個檔的預期輸出**不是 JSON 而是錯誤訊息**——上游用它們鎖住
    「這份設定必須被拒絕」。把那些當成失敗會低估覆蓋率，而且方向剛好相反：
    對那些檔案來說，**編不過才是正確的**。

    沒有分隔符的檔案整份都是設定（語料裡有兩個）。
    """
    parts = SEPARATOR.split(text, maxsplit=1)
    expects_json = len(parts) < 2 or parts[1].lstrip().startswith("{")
    return parts[0], expects_json


def classify(stderr):
    """🏷️ 把失敗歸類，因為 234 個檔的原始錯誤訊息沒人看得完。

    分類的目的是產出一份**排序過的待修清單**：同一個原因出現 30 次，
    代表修它一次解掉 30 個檔案。
    """
    text = stderr.replace("\n", " ")
    patterns = [
        (r"Unknown directive '([^']+)'", "未知 directive／子指令：{}"),
        (r"Caddy-compatible directive '([^']+)' is not supported", "已知但未實作：{}"),
        (r"Unsupported feature: ([^,;]+)", "未支援功能：{}"),
        (r"Invalid argument for '([^']+)'", "參數不合法：{}"),
        (r"Argument count.*?'([^']+)'", "參數個數：{}"),
        (r"Undefined snippet", "未定義的 snippet（import 只支援 snippet）"),
        (r"Parse error: ([^,;]{0,60})", "解析錯誤：{}"),
        (r"Duplicate", "重複定義"),
    ]
    for rx, label in patterns:
        m = re.search(rx, text)
        if m:
            captured = m.group(1).strip() if m.groups() else ""
            return label.format(captured)
    # 🧭 落到這裡代表分類器要補；把訊息前段留著好判斷。
    trimmed = re.sub(r"\s+", " ", text)
    trimmed = re.sub(r"\x1b\[[0-9;]*m", "", trimmed)
    return "未分類：" + trimmed[-140:]


def main():
    fixtures = sorted(CORPUS_DIR.glob("*.caddyfiletest"))
    if not fixtures:
        sys.exit(f"🚫 語料目錄空的：{CORPUS_DIR}")

    results = []
    for f in fixtures:
        cfg = WORK / "case.Caddyfile"
        body, expects_json = split_fixture(
            f.read_text(encoding="utf-8", errors="replace")
        )
        cfg.write_text(body)
        proc = subprocess.run(
            [str(BIN), "adapt", "--config", str(cfg)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        # 📏 The corpus asks "can the adapter compile this?", which is what
        # `caddy adapt` answers. `validate` used to stand in for it, but it
        # additionally checks that configured TLS files exist, so fixtures
        # referencing paths this machine does not have failed for a reason
        # the corpus never asked about. Exit status zero is the whole
        # contract; stdout is the adapted JSON and is not compared here.
        compiled = proc.returncode == 0
        # 🎯 「正確」對兩種檔案的意思是相反的：預期 JSON 的要編得過，
        # 預期錯誤的要被拒絕。
        correct = compiled if expects_json else not compiled
        results.append(
            {
                "fixture": f.name,
                "expects": "json" if expects_json else "rejection",
                "compiles": compiled,
                "correct": correct,
                "reason": None if correct else classify(proc.stdout + proc.stderr)
                if expects_json
                else "應該被拒絕，卻編得過（fail-open）",
            }
        )

    passed = [r for r in results if r["correct"]]
    failed = [r for r in results if not r["correct"]]
    reasons = Counter(r["reason"] for r in failed)

    (OUT / "baseline.json").write_text(
        json.dumps(
            {
                "corpus": str(CORPUS_DIR),
                "binary_sha256": subprocess.run(
                    ["shasum", "-a", "256", str(BIN)], capture_output=True, text=True
                ).stdout.split()[0],
                "total": len(results),
                "correct": len(passed),
                "results": results,
            },
            ensure_ascii=False,
            indent=1,
        ),
        encoding="utf-8",
    )

    lines = [
        "# 📚 上游 Caddyfile 語料的覆蓋率\n\n",
        f"語料：`{CORPUS_DIR}`\n\n",
        f"**{len(passed)}／{len(results)} 份設定的結果正確**"
        f"（{100 * len(passed) // max(len(results), 1)}%）。\n\n",
        "只量「編不編得過」。預期 JSON 是上游 schema，不與我們的逐位元比對——"
        "行為對照走 `compare.py`。\n\n",
        "## 🚫 失敗原因，按影響檔數排序\n\n",
        "| 檔數 | 原因 |\n|---:|---|\n",
    ]
    for reason, count in reasons.most_common():
        lines.append(f"| {count} | {reason} |\n")

    lines.append("\n## 📋 逐檔結果\n\n| 檔案 | 結果 |\n|---|---|\n")
    for r in results:
        mark = "👍" if r["correct"] else "🚫"
        lines.append(f"| `{r['fixture']}` | {mark} {r['reason'] or ''} |\n")
    (OUT / "CORPUS.md").write_text("".join(lines), encoding="utf-8")

    rej = [r for r in results if r["expects"] == "rejection"]
    print(f"📊 {len(passed)}／{len(results)} 正確"
          f"（其中 {len(rej)} 個檔的正確結果是「被拒絕」）\n")
    print("🚫 失敗原因（前 15）：")
    for reason, count in reasons.most_common(15):
        print(f"   {count:4d}  {reason}")


if __name__ == "__main__":
    main()
