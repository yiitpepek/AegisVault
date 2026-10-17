#!/usr/bin/env python3
"""PoC 13 (V-17): Portfoy modulunde dogrulanmamis adres URL yoluna gomuluyor.

fetch_live_btc_balance(address) adresi hic dogrulamadan
f"https://blockchain.info/q/addressbalance/{addr}" icine koyar.
UI'daki validate_crypto_address() derinlemesine savunma olarak FONKSIYON ICINDE yoktur.
"""
import os
import sys
import shutil

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SANDBOX = "/tmp/opencode/aegis_poc/poc13"
shutil.rmtree(SANDBOX, ignore_errors=True)
os.makedirs(SANDBOX)
os.chdir(SANDBOX)
sys.path.insert(0, PROJECT_DIR)

import crypto_portfolio

captured = {}


class FakeResp:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    @property
    def status(self):
        return 200

    def read(self):
        return b"0"


orig_urlopen = crypto_portfolio.urllib.request.urlopen


def spy_urlopen(req, timeout=None):
    captured["url"] = req.full_url if hasattr(req, "full_url") else str(req)
    return FakeResp()


def banner(title):
    print("\n" + "=" * 72)
    print(" " + title)
    print("=" * 72)


banner("PoC 13: Adres -> URL enjeksiyonu (istek manipülasyonu)")

malicious = "bc1qxyz/../../admin?redirect=evil#frag"
ok_valid, why = crypto_portfolio.validate_crypto_address("BTC", malicious)
print(f"[1] validate_crypto_address(malicious) -> {ok_valid} ({why})")

crypto_portfolio.urllib.request.urlopen = spy_urlopen
crypto_portfolio.fetch_live_btc_balance(malicious)
crypto_portfolio.urllib.request.urlopen = orig_urlopen

print(f"[2] Fonksiyon dogrulama YAPMADAN istegi atti: {captured['url']}")
print(f"[3] Duzeltilmis host sabit kaldigi icin SSRF yok; ancak yol/sorgu/fragment saldirgan")
print("    girdisiyle degistirilebiliyor (ör. API davranisini bozma, istek yonlendirme).")

print("\n[4] Kanit: fonksiyon icinde validate cagrisi yok:")
import inspect
src = inspect.getsource(crypto_portfolio.fetch_live_btc_balance)
for line in src.splitlines():
    if "url" in line or "validate" in line:
        print(f"    {line.strip()}")

print("\n" + "-" * 72)
print("KANIT: Adres URL'ye gomulmeden once kodlanmiyor/dogrulanmiyor.")
print("       Oneri: urllib.parse.quote(addr, safe='') + fonksiyon ici regex dogrulamasi.")
print("-" * 72)
