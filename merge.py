#!/usr/bin/env python3
"""Mescla várias listas de bloqueio DNS em uma só, sem repetidos.

- Aceita formato hosts (0.0.0.0 dominio) e Adblock (||dominio^).
- Remove domínios repetidos e subdomínios já cobertos por um domínio pai
  (||pai.com^ já bloqueia sub.pai.com).
- Regras com modificadores ($important, $client=...), exceções (@@) e
  regex são mantidas como estão, apenas sem duplicatas.
"""
import os
import re
import sys
import urllib.request
from datetime import datetime, timezone

R = "https://adguardteam.github.io/HostlistsRegistry/assets/"
SOURCES = [
    ("AdGuard DNS filter", R + "filter_1.txt"),
    ("Dandelion Sprout's Anti-Malware", R + "filter_12.txt"),
    ("AdGuard DNS Popup Hosts", R + "filter_59.txt"),
    ("Phishing URL Blocklist", R + "filter_30.txt"),
    ("StevenBlack fakenews-gambling-porn",
     "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts"),
    ("HaGeZi Pro",
     "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt"),
    ("Blocklist Project - Adult",
     "https://raw.githubusercontent.com/blocklistproject/Lists/master/porn.txt"),
    ("HaGeZi Ultimate", R + "filter_49.txt"),
    ("OISD Big", R + "filter_27.txt"),
    ("uBlock Badware risks", R + "filter_50.txt"),
]

DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$")
ADBLOCK_RE = re.compile(r"^\|\|([^/\^\$\*|]+)\^$")          # ||dominio^
ALLOW_RE = re.compile(r"^@@\|\|([^/\^\$\*|]+)\^$")          # @@||dominio^
HOSTS_IPS = {"0.0.0.0", "127.0.0.1", "::", "::1"}
HOSTS_SKIP = {"localhost", "localhost.localdomain", "local", "broadcasthost",
              "ip6-localhost", "ip6-loopback", "0.0.0.0"}
COSMETIC = ("##", "#@#", "#?#", "#$#", "$$")

MAX_FAILS = int(os.environ.get("MAX_FAILS", "1"))


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "adguard-merge/1.0"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read().decode("utf-8", errors="ignore")


def parse(text, blocks, allows, others):
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "!#[":
            continue  # vazio, comentário (! ou #) ou cabeçalho [Adblock Plus]
        if any(c in line for c in COSMETIC):
            continue

        m = ALLOW_RE.match(line)
        if m and DOMAIN_RE.match(m.group(1).lower()):
            allows.add(m.group(1).lower())
            continue

        m = ADBLOCK_RE.match(line)
        if m and DOMAIN_RE.match(m.group(1).lower()):
            blocks.add(m.group(1).lower())
            continue

        parts = line.split()
        if parts[0] in HOSTS_IPS and len(parts) >= 2:
            for d in parts[1:]:
                if d.startswith("#"):
                    break
                d = d.lower()
                if d not in HOSTS_SKIP and DOMAIN_RE.match(d) and "." in d:
                    blocks.add(d)
            continue

        # qualquer outra regra válida (modificadores, regex, wildcard...)
        if line.startswith(("||", "@@", "/", "|")) or "$" in line:
            others.add(line)


def collapse(blocks):
    """Remove subdomínios cobertos por um domínio pai já bloqueado."""
    kept = set()
    for d in blocks:
        labels = d.split(".")
        covered = False
        for i in range(1, len(labels) - 1):
            if ".".join(labels[i:]) in blocks:
                covered = True
                break
        if not covered:
            kept.add(d)
    return kept


def main():
    blocks, allows, others = set(), set(), set()
    fails = []
    for name, url in SOURCES:
        try:
            before = len(blocks)
            parse(fetch(url), blocks, allows, others)
            print(f"OK   {name}: +{len(blocks) - before} domínios novos", flush=True)
        except Exception as e:  # noqa: BLE001
            fails.append(name)
            print(f"FAIL {name}: {e}", file=sys.stderr, flush=True)

    if len(fails) > MAX_FAILS:
        sys.exit(f"Muitas fontes falharam ({len(fails)}): {fails}. Nada foi gerado.")

    total_before = len(blocks)
    blocks = collapse(blocks)
    print(f"Domínios únicos: {total_before} -> {len(blocks)} após remover subdomínios cobertos")

    if len(blocks) < 500_000 and not os.environ.get("ALLOW_SMALL"):
        sys.exit("Resultado pequeno demais (<500k), abortando para não publicar lista quebrada.")

    out = sys.argv[1] if len(sys.argv) > 1 else "merged.txt"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write("! Title: Lista mesclada (sem repetidos)\n")
        f.write(f"! Last modified: {now}\n")
        f.write(f"! Domínios: {len(blocks)} | Exceções: {len(allows)} | Outras regras: {len(others)}\n")
        f.write("! Fontes: " + "; ".join(n for n, _ in SOURCES) + "\n")
        for a in sorted(allows):
            f.write(f"@@||{a}^\n")
        for line in sorted(others):
            f.write(line + "\n")
        for d in sorted(blocks):
            f.write(f"||{d}^\n")
    print(f"Gerado {out}")


if __name__ == "__main__":
    main()
