from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
import tempfile
import threading
import unittest
import requests

from lan_transfer.crypto import (
    decode_and_validate_key,
    generate_credentials,
    get_client_auth_token,
    get_decryptor,
    get_encryptor,
    get_key_verification_hash,
    verify_key,
    verify_pin,
)
from lan_transfer.receiver import receive_file
from lan_transfer.sender import LanTransferServer
from lan_transfer.utils import resolve_output_path, safe_extract_tar, sanitize_filename


class _ServerRunner:
    """Context manager to run LanTransferServer in a background thread for tests."""

    def __init__(self, filepath: str, users: int = 1, compress: bool = False, max_pin_attempts_per_ip: int = 5):
        self.server = LanTransferServer(
            ("127.0.0.1", 0),
            filepath=filepath,
            users=users,
            compress=compress,
            quiet=True,
            max_pin_attempts_per_ip=max_pin_attempts_per_ip,
        )
        self.address = f"127.0.0.1:{self.server.server_address[1]}"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "_ServerRunner":
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.server.shutdown()
        self.server.server_close()
        self._thread.join(timeout=3)


class TestCryptoAndUtils(unittest.TestCase):
    def test_credentials_and_hmac(self):
        pin, key_bytes, key_b64 = generate_credentials()
        self.assertEqual(len(pin), 4)
        self.assertTrue(pin.isdigit())
        self.assertEqual(decode_and_validate_key(key_b64), key_bytes)

        self.assertTrue(verify_pin(pin, pin))
        self.assertFalse(verify_pin("9999" if pin != "9999" else "0000", pin))
        self.assertFalse(verify_pin(None, pin))

        tag = get_key_verification_hash(key_bytes)
        self.assertTrue(verify_key(key_bytes, tag))
        _, other_key, _ = generate_credentials()
        self.assertFalse(verify_key(other_key, tag))

        with self.assertRaises(ValueError):
            decode_and_validate_key("not-valid-base64!!!")
        with self.assertRaises(ValueError):
            decode_and_validate_key("c2hvcnQ=")  # "short" != 32 bytes

    def test_ctr_arbitrary_offset_seek_and_wraparound(self):
        _, key_bytes, _ = generate_credentials()
        # Test nonce near 128-bit max to verify modular wraparound
        nonce = b"\xff" * 15 + b"\xfe"
        plaintext = os.urandom(200_000)

        enc_full = get_encryptor(key_bytes, nonce, byte_offset=0)
        ciphertext = enc_full.update(plaintext) + enc_full.finalize()

        for offset in (0, 1, 15, 16, 17, 31, 32, 77_777, 199_999):
            dec = get_decryptor(key_bytes, nonce, byte_offset=offset)
            recovered = dec.update(ciphertext[offset:]) + dec.finalize()
            self.assertEqual(recovered, plaintext[offset:], f"Failed at byte offset {offset}")

    def test_sanitization_collision_and_tarslip_protection(self):
        self.assertEqual(sanitize_filename("../../etc/passwd"), "passwd")
        self.assertEqual(sanitize_filename("..\\..\\Windows\\system.ini"), "system.ini")
        self.assertEqual(sanitize_filename("Report: 2026?.pdf"), "Report_ 2026_.pdf")
        self.assertEqual(sanitize_filename("..."), "downloaded_file")

        with tempfile.TemporaryDirectory() as tmpdir:
            existing = os.path.join(tmpdir, "archive.tar.gz")
            with open(existing, "wb") as f:
                f.write(b"x")
            resolved, renamed = resolve_output_path("archive.tar.gz", output=tmpdir, overwrite=False)
            self.assertTrue(renamed)
            self.assertEqual(os.path.basename(resolved), "archive (1).tar.gz")

            # Craft malicious tar attempting path traversal
            evil_tar = os.path.join(tmpdir, "evil.tar")
            with tarfile.open(evil_tar, "w") as tf:
                info = tarfile.TarInfo(name="../escaped.txt")
                payload = b"malicious"
                info.size = len(payload)
                tf.addfile(info, io.BytesIO(payload))

            extract_sub = os.path.join(tmpdir, "safe_out")
            try:
                safe_extract_tar(evil_tar, extract_sub)
            except Exception:
                pass
            self.assertFalse(os.path.exists(os.path.join(tmpdir, "escaped.txt")))


class TestEndToEndTransfers(unittest.TestCase):
    def test_single_file_transfer_and_auto_filename(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src_file = os.path.join(tmpdir, "My Sample File.bin")
            data = os.urandom(1_500_000)
            with open(src_file, "wb") as f:
                f.write(data)

            out_dir = os.path.join(tmpdir, "received")
            with _ServerRunner(src_file, users=1) as runner:
                ok = receive_file(
                    address=runner.address,
                    filename=None,  # Auto-detect filename from server header
                    pin=runner.server.pin,
                    key_b64=runner.server.key_b64,
                    output=out_dir,
                    quiet=True,
                )
                self.assertTrue(ok)
                self.assertEqual(runner.server.downloads_remaining, 0)

            received_path = os.path.join(out_dir, "My Sample File.bin")
            self.assertTrue(os.path.isfile(received_path))
            with open(received_path, "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), hashlib.sha256(data).hexdigest())

    def test_wrong_pin_and_wrong_key_preserve_slot(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src_file = os.path.join(tmpdir, "secret.dat")
            # Tiny 32-byte payload fits inside any OS TCP buffer, proving pre-stream X-LAN-AUTH works
            payload = b"top-secret-tiny-payload-32-bytes"
            with open(src_file, "wb") as f:
                f.write(payload)

            out_dir = os.path.join(tmpdir, "out")
            _, _, wrong_key_b64 = generate_credentials()

            with _ServerRunner(src_file, users=1) as runner:
                wrong_pin = "0000" if runner.server.pin != "0000" else "1111"

                # 1. Wrong PIN must fail and NOT decrement downloads_remaining
                self.assertFalse(
                    receive_file(runner.address, "secret.dat", wrong_pin, runner.server.key_b64, out_dir, quiet=True)
                )
                self.assertEqual(runner.server.downloads_remaining, 1)

                # 2. Wrong Key must fail and NOT decrement downloads_remaining
                self.assertFalse(
                    receive_file(runner.address, "secret.dat", runner.server.pin, wrong_key_b64, out_dir, quiet=True)
                )
                self.assertEqual(runner.server.downloads_remaining, 1)

                # 3. Valid credentials succeed
                self.assertTrue(
                    receive_file(
                        runner.address,
                        "secret.dat",
                        runner.server.pin,
                        runner.server.key_b64,
                        out_dir,
                        quiet=True,
                    )
                )
                self.assertEqual(runner.server.downloads_remaining, 0)

    def test_pin_bruteforce_lockout(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src_file = os.path.join(tmpdir, "doc.txt")
            with open(src_file, "wb") as f:
                f.write(b"protected")

            out_dir = os.path.join(tmpdir, "out")
            with _ServerRunner(src_file, users=1, max_pin_attempts_per_ip=3) as runner:
                wrong_pin = "0000" if runner.server.pin != "0000" else "1111"
                for _ in range(3):
                    self.assertFalse(
                        receive_file(runner.address, "doc.txt", wrong_pin, runner.server.key_b64, out_dir, quiet=True)
                    )
                # Even the valid PIN must now be blocked (HTTP 429) for this IP
                resp = requests.get(
                    f"http://{runner.address}/doc.txt",
                    headers={"X-LAN-PIN": runner.server.pin},
                    timeout=5,
                )
                self.assertEqual(resp.status_code, 429)

    def test_resumable_download_from_unaligned_offset(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src_file = os.path.join(tmpdir, "movie.mp4")
            full_data = os.urandom(5_000_000)
            with open(src_file, "wb") as f:
                f.write(full_data)

            out_dir = os.path.join(tmpdir, "downloads")
            os.makedirs(out_dir, exist_ok=True)
            cutoff = 777_777  # Intentionally non-16-byte-aligned offset

            with _ServerRunner(src_file, users=1) as runner:
                # Simulate interrupted initial download saving cutoff bytes to .part
                with requests.get(
                    f"http://{runner.address}/movie.mp4",
                    headers={
                        "X-LAN-PIN": runner.server.pin,
                        "X-LAN-AUTH": get_client_auth_token(runner.server.key_bytes),
                    },
                    stream=True,
                    timeout=5,
                ) as resp:
                    self.assertEqual(resp.status_code, 200)
                    transfer_id = resp.headers["X-LAN-TRANSFER-ID"]
                    import base64

                    nonce = base64.b64decode(resp.headers["X-LAN-NONCE"])
                    dec = get_decryptor(runner.server.key_bytes, nonce, byte_offset=0)
                    raw_enc = resp.raw.read(cutoff)
                    partial_plain = dec.update(raw_enc)

                part_path = os.path.join(out_dir, "movie.mp4.part")
                meta_path = os.path.join(out_dir, "movie.mp4.part.meta")
                with open(part_path, "wb") as pf:
                    pf.write(partial_plain)
                with open(meta_path, "w", encoding="utf-8") as mf:
                    json.dump({"transfer_id": transfer_id, "filename": "movie.mp4"}, mf)

                # Slot should still be available since connection aborted early
                self.assertEqual(runner.server.downloads_remaining, 1)

                # Now run receive_file — it must resume via 206 Partial Content and finish cleanly
                ok = receive_file(
                    address=runner.address,
                    filename="movie.mp4",
                    pin=runner.server.pin,
                    key_b64=runner.server.key_b64,
                    output=out_dir,
                    resume=True,
                    quiet=True,
                )
                self.assertTrue(ok)
                self.assertEqual(runner.server.downloads_remaining, 0)

            final_file = os.path.join(out_dir, "movie.mp4")
            self.assertTrue(os.path.isfile(final_file))
            self.assertFalse(os.path.exists(part_path))
            self.assertFalse(os.path.exists(meta_path))
            with open(final_file, "rb") as f:
                self.assertEqual(f.read(), full_data)

    def test_directory_streaming_compressed_and_extract_plus_abort_cleanup(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src_dir = os.path.join(tmpdir, "ProjectFolder")
            sub_dir = os.path.join(src_dir, "subdir")
            os.makedirs(sub_dir)
            file_a = os.urandom(4_500_000)
            file_b = b"Hello LAN Transfer compressed tar stream!\n" * 5000
            with open(os.path.join(src_dir, "a.bin"), "wb") as f:
                f.write(file_a)
            with open(os.path.join(sub_dir, "b.txt"), "wb") as f:
                f.write(file_b)

            out_dir = os.path.join(tmpdir, "extracted_dest")
            with _ServerRunner(src_dir, users=1, compress=True) as runner:
                # First abort mid-stream to ensure TarStreamer cleans up without hanging or losing slot
                with requests.get(
                    f"http://{runner.address}/ProjectFolder.tar.gz",
                    headers={
                        "X-LAN-PIN": runner.server.pin,
                        "X-LAN-AUTH": get_client_auth_token(runner.server.key_bytes),
                    },
                    stream=True,
                    timeout=5,
                ) as resp:
                    _ = next(resp.iter_content(1024))
                # Complete full compressed folder transfer + automatic extraction
                ok = receive_file(
                    address=runner.address,
                    filename=None,
                    pin=runner.server.pin,
                    key_b64=runner.server.key_b64,
                    output=out_dir,
                    extract=True,
                    quiet=True,
                )
                self.assertTrue(ok)
                self.assertEqual(runner.server.downloads_remaining, 0)

            with open(os.path.join(out_dir, "ProjectFolder", "a.bin"), "rb") as f:
                self.assertEqual(f.read(), file_a)
            with open(os.path.join(out_dir, "ProjectFolder", "subdir", "b.txt"), "rb") as f:
                self.assertEqual(f.read(), file_b)

    def test_multiplayer_concurrent_downloads(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src_file = os.path.join(tmpdir, "shared.bin")
            payload = os.urandom(1_200_000)
            with open(src_file, "wb") as f:
                f.write(payload)

            out1 = os.path.join(tmpdir, "u1")
            out2 = os.path.join(tmpdir, "u2")
            results = [False, False]

            with _ServerRunner(src_file, users=2) as runner:
                def worker(idx: int, dest: str) -> None:
                    results[idx] = receive_file(
                        address=runner.address,
                        filename="shared.bin",
                        pin=runner.server.pin,
                        key_b64=runner.server.key_b64,
                        output=dest,
                        quiet=True,
                    )

                t1 = threading.Thread(target=worker, args=(0, out1))
                t2 = threading.Thread(target=worker, args=(1, out2))
                t1.start()
                t2.start()
                t1.join(timeout=10)
                t2.join(timeout=10)

                self.assertTrue(all(results))
                self.assertEqual(runner.server.completed_downloads, 2)
                self.assertEqual(runner.server.downloads_remaining, 0)

            for folder in (out1, out2):
                with open(os.path.join(folder, "shared.bin"), "rb") as f:
                    self.assertEqual(f.read(), payload)


if __name__ == "__main__":
    unittest.main()
