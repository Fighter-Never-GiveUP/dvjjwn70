#!/usr/bin/env python3
"""
verify.py - Public verification of audit chain anchors

Standalone verifier. Anyone can run this to verify that anchors in this
repository are correctly signed with the public key declared in public.key.

Usage:
    python verify.py                       # Verify all anchors
    python verify.py anchors/2026-W18.json # Verify a specific anchor

No private key is required - only the public key (public.key) is used.
PyNaCl must be installed: pip install pynacl
"""

import base64
import hashlib
import json
import sys
from pathlib import Path

try:
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError
except ImportError:
    print("ERREUR: PyNaCl non installe. Lance : pip install pynacl", file=sys.stderr)
    sys.exit(2)


def parse_openssh_pub(blob: bytes) -> VerifyKey:
    """Parse une cle publique au format SSH (ssh-ed25519 AAAAC3...)."""
    pos = 0
    algo_len = int.from_bytes(blob[pos:pos+4], 'big')
    pos += 4
    algo = blob[pos:pos+algo_len].decode('ascii')
    pos += algo_len
    if algo != "ssh-ed25519":
        raise ValueError(f"Algo non supporte : {algo}")
    pk_len = int.from_bytes(blob[pos:pos+4], 'big')
    pos += 4
    return VerifyKey(blob[pos:pos+pk_len])


def load_pubkey(path: Path) -> tuple:
    """Charge la cle publique et retourne (VerifyKey, fingerprint_sha256)."""
    line = path.read_text(encoding='ascii').strip()
    parts = line.split()
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise ValueError(f"{path}: format ssh-ed25519 attendu")
    blob = base64.b64decode(parts[1])
    fp = hashlib.sha256(blob).digest()
    fingerprint = "SHA256:" + base64.b64encode(fp).decode('ascii').rstrip('=')
    return parse_openssh_pub(blob), fingerprint


def canonical_json(obj) -> str:
    return json.dumps(obj, separators=(',', ':'), sort_keys=True, ensure_ascii=False)


def verify_anchor(anchor_path: Path, vk: VerifyKey, expected_fp: str) -> dict:
    """Verifie une ancre. Retourne un dict avec status."""
    try:
        anchor = json.loads(anchor_path.read_text(encoding='utf-8'))
    except json.JSONDecodeError as e:
        return {"ok": False, "error": f"JSON invalide: {e}"}

    if 'signature' not in anchor:
        return {"ok": False, "error": "Champ 'signature' manquant"}

    fp = anchor.get('ed25519_pubkey_fingerprint')
    if fp != expected_fp:
        return {
            "ok": False,
            "error": f"Fingerprint mismatch (ancre: {fp}, attendu: {expected_fp})"
        }

    sig_b64 = anchor.pop('signature')
    canonical = canonical_json(anchor)

    try:
        sig_bytes = base64.b64decode(sig_b64)
        vk.verify(canonical.encode('utf-8'), sig_bytes)
    except BadSignatureError:
        return {"ok": False, "error": "Signature Ed25519 INVALIDE - ancre alteree"}
    except Exception as e:
        return {"ok": False, "error": f"Erreur verification : {e}"}

    return {
        "ok": True,
        "iso_week": anchor['iso_week'],
        "anchor_date": anchor['anchor_date'],
        "last_index": anchor['chain_state']['last_index'],
        "chain_hash": anchor['chain_state']['chain_hash_sha256'],
    }


def main():
    repo_root = Path(__file__).parent
    pubkey_file = repo_root / "public.key"
    anchors_dir = repo_root / "anchors"

    if not pubkey_file.exists():
        print(f"[FAIL] {pubkey_file} introuvable", file=sys.stderr)
        return 2

    try:
        vk, fingerprint = load_pubkey(pubkey_file)
    except Exception as e:
        print(f"[FAIL] Impossible de charger {pubkey_file}: {e}", file=sys.stderr)
        return 2

    print(f"Cle publique : {fingerprint}")
    print()

    # Determiner les ancres a verifier
    if len(sys.argv) > 1:
        targets = [Path(p) for p in sys.argv[1:]]
    else:
        if not anchors_dir.exists():
            print(f"[INFO] Aucun dossier anchors/")
            return 0
        targets = sorted(anchors_dir.glob("*.json"))

    if not targets:
        print(f"[INFO] Aucune ancre a verifier")
        return 0

    failed = 0
    for anchor_path in targets:
        result = verify_anchor(anchor_path, vk, fingerprint)
        if result['ok']:
            print(f"[OK]   {anchor_path.name}")
            print(f"       Date    : {result['anchor_date']}")
            print(f"       Index   : {result['last_index']}")
            print(f"       Hash    : {result['chain_hash'][:32]}...")
        else:
            print(f"[FAIL] {anchor_path.name}")
            print(f"       {result['error']}")
            failed += 1

    print()
    if failed == 0:
        print(f"OK : {len(targets)} ancre(s) verifiee(s) avec succes")
        return 0
    else:
        print(f"ECHEC : {failed}/{len(targets)} ancre(s) invalide(s)")
        return 1


if __name__ == '__main__':
    sys.exit(main())
