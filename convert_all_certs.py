"""Converte em lote todos os .pfx/.p12 legados em C:\Certificados para formato moderno.

Pula arquivos que já terminam com _modern.pfx.
Saída: mesmo diretório, nome original + _modern.pfx
"""
import getpass
import sys
from pathlib import Path

from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    load_pkcs12,
    serialize_key_and_certificates,
)

CERT_DIR = Path(r"C:\Certificados")

SKIP = {"saveInt_modern", "saveTec_modern", "dsr_modern"}


def convert_one(in_path: Path, out_path: Path) -> bool:
    in_pass = getpass.getpass(f"  Senha atual ({in_path.name}): ")

    try:
        data = in_path.read_bytes()
        p12 = load_pkcs12(data, in_pass.encode())
    except Exception as e:
        print(f"  ERRO ao carregar: {e}")
        return False

    out_pass_raw = getpass.getpass(
        f"  Nova senha ({out_path.name}) [ENTER = mesma senha]: "
    )
    out_pass = out_pass_raw or in_pass

    cert = p12.cert.certificate if p12.cert else None
    cas = [c.certificate for c in (p12.additional_certs or [])] or None
    name = (p12.cert.friendly_name if p12.cert else b"cert") or b"cert"

    new_data = serialize_key_and_certificates(
        name=name,
        key=p12.key,
        cert=cert,
        cas=cas,
        encryption_algorithm=BestAvailableEncryption(out_pass.encode()),
    )

    out_path.write_bytes(new_data)
    print(f"  OK: {out_path.name} ({len(new_data)} bytes)\n")
    return True


def main() -> None:
    certs = sorted(
        f for f in CERT_DIR.iterdir()
        if f.suffix.lower() in {".pfx", ".p12"} and f.stem not in SKIP
    )

    if not certs:
        print("Nenhum certificado para converter.")
        return

    print(f"Encontrados {len(certs)} certificado(s) para converter:\n")
    for i, c in enumerate(certs, 1):
        print(f"  {i}. {c.name}")

    print()
    errors = []

    for cert in certs:
        out_path = CERT_DIR / f"{cert.stem}_modern.pfx"

        if out_path.exists():
            resp = input(f"[{cert.name}] Saída '{out_path.name}' já existe. Sobrescrever? (s/N): ").strip().lower()
            if resp != "s":
                print("  Pulado.\n")
                continue

        print(f"\n--- {cert.name} ---")
        success = convert_one(cert, out_path)
        if not success:
            errors.append(cert.name)

    print("\n=== Concluído ===")
    if errors:
        print(f"Com erro ({len(errors)}): {', '.join(errors)}")
    else:
        print("Todos convertidos com sucesso.")


if __name__ == "__main__":
    main()
