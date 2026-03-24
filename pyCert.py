#!/usr/bin/env python3
"""
FreeTSA Timestamp Tool
Crea e verifica marche temporali usando freetsa.org (RFC 3161)
Requisiti:
-python3
-pip install requests
"""

import os
import sys
import hashlib
import subprocess
import tempfile
import urllib.request
import urllib.error
import struct
import base64
import json
from pathlib import Path
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading


# ---------------------------------------------------------------------------
# Colori e stile
# ---------------------------------------------------------------------------
BG      = "#0d1117"
PANEL   = "#161b22"
BORDER  = "#30363d"
ACCENT  = "#58a6ff"
GREEN   = "#3fb950"
RED     = "#f85149"
YELLOW  = "#d29922"
TEXT    = "#e6edf3"
MUTED   = "#8b949e"
FONT_MONO = ("Courier New", 10)
FONT_UI   = ("Segoe UI", 10) if sys.platform == "win32" else ("SF Pro Display", 10)


# ---------------------------------------------------------------------------
# Utilità TSQ / TSR
# ---------------------------------------------------------------------------

def sha512_file(filepath: str) -> bytes:
    h = hashlib.sha512()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.digest()


def _encode_der_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    elif n < 0x100:
        return bytes([0x81, n])
    else:
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])


def _der(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _encode_der_length(len(content)) + content


def build_tsq(digest: bytes) -> bytes:
    """
    Costruisce una TimeStampReq (RFC 3161) in DER per SHA-512.
    Struttura:
      TimeStampReq ::= SEQUENCE {
        version      INTEGER { v1(1) },
        messageImprint MessageImprint,
        nonce        INTEGER OPTIONAL,   <- omesso
        certReq      BOOLEAN OPTIONAL    <- omesso
      }
      MessageImprint ::= SEQUENCE {
        hashAlgorithm AlgorithmIdentifier,
        hashedMessage OCTET STRING
      }
    OID SHA-512 = 2.16.840.1.101.3.4.2.3  -> 60 86 48 01 65 03 04 02 03
    """
    sha512_oid_value = bytes([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03])
    oid = _der(0x06, sha512_oid_value)
    null = _der(0x05, b"")
    alg_id = _der(0x30, oid + null)
    hashed_msg = _der(0x04, digest)
    msg_imprint = _der(0x30, alg_id + hashed_msg)
    version = _der(0x02, b"\x01")
    tsreq = _der(0x30, version + msg_imprint)
    return tsreq


def send_tsq(tsq_bytes: bytes) -> bytes:
    """Invia la query a freetsa.org e restituisce i byte TSR."""
    url = "https://freetsa.org/tsr"
    req = urllib.request.Request(
        url,
        data=tsq_bytes,
        headers={"Content-Type": "application/timestamp-query"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()


def download_certs(dest_dir: str) -> tuple[str, str]:
    """Scarica tsa.crt e cacert.pem se non già presenti. Restituisce i path."""
    tsa_path  = os.path.join(dest_dir, "tsa.crt")
    ca_path   = os.path.join(dest_dir, "cacert.pem")
    for url, path in [
        ("https://freetsa.org/files/tsa.crt",    tsa_path),
        ("https://freetsa.org/files/cacert.pem", ca_path),
    ]:
        if not os.path.exists(path):
            urllib.request.urlretrieve(url, path)
    return tsa_path, ca_path


def openssl_available() -> bool:
    try:
        subprocess.run(["openssl", "version"], capture_output=True, check=True)
        return True
    except Exception:
        return False


def verify_tsr(tsr_path: str, tsq_path: str, certs_dir: str) -> tuple[bool, str]:
    """Verifica TSR con openssl. Restituisce (ok, output)."""
    tsa_crt, ca_pem = download_certs(certs_dir)
    cmd = [
        "openssl", "ts", "-verify",
        "-in", tsr_path,
        "-queryfile", tsq_path,
        "-CAfile", ca_pem,
        "-untrusted", tsa_crt,
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    ok  = res.returncode == 0
    out = (res.stdout + res.stderr).strip()
    return ok, out


def tsr_info(tsr_path: str) -> str:
    """Legge le info del TSR con openssl ts -reply -text."""
    cmd = ["openssl", "ts", "-reply", "-in", tsr_path, "-text"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    return (res.stdout + res.stderr).strip()


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("FreeTSA Timestamp Tool")
        self.configure(bg=BG)
        self.resizable(True, True)
        self.minsize(820, 600)

        self._certs_dir = str(Path.home() / ".freetsa_certs")
        os.makedirs(self._certs_dir, exist_ok=True)

        self._build_ui()
        self._check_openssl()

    # ------------------------------------------------------------------ UI --

    def _build_ui(self):
        # ── Header ──────────────────────────────────────────────────────────
        hdr = tk.Frame(self, bg=BG, pady=16)
        hdr.pack(fill="x", padx=24)
        tk.Label(hdr, text="⏱  FreeTSA", font=("Courier New", 22, "bold"),
                 fg=ACCENT, bg=BG).pack(side="left")
        tk.Label(hdr, text="  Timestamp Tool  —  RFC 3161",
                 font=FONT_UI, fg=MUTED, bg=BG).pack(side="left", pady=4)

        self._ssl_lbl = tk.Label(hdr, text="", font=FONT_UI, bg=BG)
        self._ssl_lbl.pack(side="right")

        ttk.Separator(self, orient="horizontal").pack(fill="x", padx=24)

        # ── Notebook ─────────────────────────────────────────────────────────
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TNotebook",            background=BG, borderwidth=0)
        style.configure("TNotebook.Tab",        background=PANEL, foreground=MUTED,
                                                padding=[14, 6], font=FONT_UI)
        style.map("TNotebook.Tab",
                  background=[("selected", BG)],
                  foreground=[("selected", TEXT)])
        style.configure("TFrame", background=BG)

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=24, pady=12)

        self._tab_create = ttk.Frame(nb)
        self._tab_verify = ttk.Frame(nb)
        self._tab_batch  = ttk.Frame(nb)

        nb.add(self._tab_create, text="  Crea Marca Temporale  ")
        nb.add(self._tab_verify, text="  Verifica TSR  ")
        nb.add(self._tab_batch,  text="  Batch  ")

        self._build_create_tab()
        self._build_verify_tab()
        self._build_batch_tab()

        # ── Log / Console ────────────────────────────────────────────────────
        ttk.Separator(self, orient="horizontal").pack(fill="x", padx=24)
        log_frame = tk.Frame(self, bg=BG)
        log_frame.pack(fill="both", expand=False, padx=24, pady=(4, 12))
        tk.Label(log_frame, text="Console", font=FONT_UI, fg=MUTED, bg=BG).pack(anchor="w")
        self._log = scrolledtext.ScrolledText(
            log_frame, height=7, bg=PANEL, fg=TEXT,
            font=FONT_MONO, relief="flat", bd=0,
            insertbackground=TEXT, state="disabled",
        )
        self._log.pack(fill="both", expand=True)
        self._log.tag_config("ok",   foreground=GREEN)
        self._log.tag_config("err",  foreground=RED)
        self._log.tag_config("info", foreground=ACCENT)
        self._log.tag_config("warn", foreground=YELLOW)

    # ── Tab: Crea ────────────────────────────────────────────────────────────

    def _build_create_tab(self):
        f = self._tab_create
        pad = {"padx": 20, "pady": 8}

        # File input
        row1 = tk.Frame(f, bg=BG); row1.pack(fill="x", **pad)
        tk.Label(row1, text="File da timbrare:", fg=TEXT, bg=BG,
                 font=FONT_UI, width=22, anchor="w").pack(side="left")
        self._create_file_var = tk.StringVar()
        ent = tk.Entry(row1, textvariable=self._create_file_var,
                       bg=PANEL, fg=TEXT, font=FONT_MONO, relief="flat",
                       insertbackground=TEXT, bd=4)
        ent.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self._btn(row1, "Sfoglia", self._browse_create_file).pack(side="left")

        # Output dir
        row2 = tk.Frame(f, bg=BG); row2.pack(fill="x", **pad)
        tk.Label(row2, text="Cartella output:", fg=TEXT, bg=BG,
                 font=FONT_UI, width=22, anchor="w").pack(side="left")
        self._create_out_var = tk.StringVar()
        ent2 = tk.Entry(row2, textvariable=self._create_out_var,
                        bg=PANEL, fg=TEXT, font=FONT_MONO, relief="flat",
                        insertbackground=TEXT, bd=4)
        ent2.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self._btn(row2, "Sfoglia", self._browse_create_out).pack(side="left")

        # Info box
        info = tk.Frame(f, bg=PANEL, padx=12, pady=8)
        info.pack(fill="x", padx=20, pady=(4, 8))
        tk.Label(info, text="ℹ  Verranno generati:", fg=MUTED, bg=PANEL, font=FONT_UI).pack(anchor="w")
        for line in ["• <nome>.tsq  — timestamp query (SHA-512)",
                     "• <nome>.tsr  — risposta del server FreeTSA",
                     "• <nome>_timestamp_info.txt  — riepilogo leggibile"]:
            tk.Label(info, text=line, fg=MUTED, bg=PANEL,
                     font=("Courier New", 9)).pack(anchor="w")

        # Bottone principale
        row3 = tk.Frame(f, bg=BG); row3.pack(fill="x", padx=20, pady=4)
        self._btn(row3, "⏱  Crea Marca Temporale", self._do_create,
                  bg=ACCENT, fg=BG, font=("Courier New", 11, "bold")).pack(side="left")

        # Progress
        self._create_progress = ttk.Progressbar(f, mode="indeterminate")
        self._create_progress.pack(fill="x", padx=20, pady=(0, 8))

    # ── Tab: Verifica ────────────────────────────────────────────────────────

    def _build_verify_tab(self):
        f = self._tab_verify
        pad = {"padx": 20, "pady": 8}

        for label, var_name, browse_cmd in [
            ("File TSR:", "_ver_tsr_var", "_browse_ver_tsr"),
            ("File TSQ:", "_ver_tsq_var", "_browse_ver_tsq"),
        ]:
            row = tk.Frame(f, bg=BG); row.pack(fill="x", **pad)
            tk.Label(row, text=label, fg=TEXT, bg=BG,
                     font=FONT_UI, width=22, anchor="w").pack(side="left")
            var = tk.StringVar(); setattr(self, var_name, var)
            ent = tk.Entry(row, textvariable=var, bg=PANEL, fg=TEXT,
                           font=FONT_MONO, relief="flat", insertbackground=TEXT, bd=4)
            ent.pack(side="left", fill="x", expand=True, padx=(0, 8))
            self._btn(row, "Sfoglia", getattr(self, browse_cmd)).pack(side="left")

        row_b = tk.Frame(f, bg=BG); row_b.pack(fill="x", padx=20, pady=4)
        self._btn(row_b, "🔍  Verifica", self._do_verify,
                  bg=GREEN, fg=BG, font=("Courier New", 11, "bold")).pack(side="left")
        self._btn(row_b, "📋  Info TSR", self._do_info,
                  bg=PANEL, fg=TEXT).pack(side="left", padx=(8, 0))

        self._ver_result = tk.Label(f, text="", font=("Courier New", 13, "bold"),
                                    bg=BG, pady=10)
        self._ver_result.pack(fill="x", padx=20)

    # ── Tab: Batch ───────────────────────────────────────────────────────────

    def _build_batch_tab(self):
        f = self._tab_batch
        pad = {"padx": 20, "pady": 8}

        row1 = tk.Frame(f, bg=BG); row1.pack(fill="x", **pad)
        tk.Label(row1, text="Files da timbrare:", fg=TEXT, bg=BG,
                 font=FONT_UI, width=22, anchor="w").pack(side="left")
        self._btn(row1, "Aggiungi files", self._batch_add_files).pack(side="left")
        self._btn(row1, "Svuota lista",   self._batch_clear,
                  bg=PANEL, fg=RED).pack(side="left", padx=(8, 0))

        list_frame = tk.Frame(f, bg=BG); list_frame.pack(fill="both", expand=True, padx=20)
        sb = tk.Scrollbar(list_frame)
        sb.pack(side="right", fill="y")
        self._batch_listbox = tk.Listbox(
            list_frame, bg=PANEL, fg=TEXT, font=FONT_MONO,
            selectbackground=ACCENT, selectforeground=BG,
            relief="flat", bd=0, yscrollcommand=sb.set,
        )
        self._batch_listbox.pack(fill="both", expand=True)
        sb.config(command=self._batch_listbox.yview)

        row2 = tk.Frame(f, bg=BG); row2.pack(fill="x", **pad)
        tk.Label(row2, text="Cartella output:", fg=TEXT, bg=BG,
                 font=FONT_UI, width=22, anchor="w").pack(side="left")
        self._batch_out_var = tk.StringVar()
        ent = tk.Entry(row2, textvariable=self._batch_out_var, bg=PANEL, fg=TEXT,
                       font=FONT_MONO, relief="flat", insertbackground=TEXT, bd=4)
        ent.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self._btn(row2, "Sfoglia", self._browse_batch_out).pack(side="left")

        row3 = tk.Frame(f, bg=BG); row3.pack(fill="x", padx=20, pady=4)
        self._btn(row3, "⏱  Timbra tutti", self._do_batch,
                  bg=YELLOW, fg=BG, font=("Courier New", 11, "bold")).pack(side="left")

        self._batch_progress = ttk.Progressbar(f, mode="determinate")
        self._batch_progress.pack(fill="x", padx=20, pady=(0, 8))

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _btn(self, parent, text, cmd, bg=BORDER, fg=TEXT, font=None):
        kw = dict(text=text, command=cmd, bg=bg, fg=fg,
                  relief="flat", bd=0, padx=12, pady=6,
                  cursor="hand2", activebackground=ACCENT, activeforeground=BG)
        if font:
            kw["font"] = font
        else:
            kw["font"] = FONT_UI
        return tk.Button(parent, **kw)

    def _log_write(self, msg: str, tag: str = ""):
        self._log.configure(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        self._log.insert("end", f"[{ts}] {msg}\n", tag)
        self._log.see("end")
        self._log.configure(state="disabled")

    def log_info(self, m): self.after(0, lambda: self._log_write(m, "info"))
    def log_ok  (self, m): self.after(0, lambda: self._log_write(m, "ok"))
    def log_err (self, m): self.after(0, lambda: self._log_write(m, "err"))
    def log_warn(self, m): self.after(0, lambda: self._log_write(m, "warn"))

    def _check_openssl(self):
        if openssl_available():
            self._ssl_lbl.config(text="● openssl disponibile", fg=GREEN)
            self.log_ok("openssl trovato nel PATH.")
        else:
            self._ssl_lbl.config(text="● openssl NON trovato", fg=YELLOW)
            self.log_warn("openssl non trovato: la verifica TSR non sarà disponibile.")

    # ── Browse ───────────────────────────────────────────────────────────────

    def _browse_create_file(self):
        p = filedialog.askopenfilename(title="Seleziona file")
        if p:
            self._create_file_var.set(p)
            if not self._create_out_var.get():
                self._create_out_var.set(str(Path(p).parent))

    def _browse_create_out(self):
        p = filedialog.askdirectory(title="Cartella output")
        if p: self._create_out_var.set(p)

    def _browse_ver_tsr(self):
        p = filedialog.askopenfilename(title="File TSR", filetypes=[("TSR", "*.tsr"), ("All", "*")])
        if p:
            self._ver_tsr_var.set(p)
            tsq = str(Path(p).with_suffix(".tsq"))
            if os.path.exists(tsq) and not self._ver_tsq_var.get():
                self._ver_tsq_var.set(tsq)

    def _browse_ver_tsq(self):
        p = filedialog.askopenfilename(title="File TSQ", filetypes=[("TSQ", "*.tsq"), ("All", "*")])
        if p: self._ver_tsq_var.set(p)

    def _batch_add_files(self):
        files = filedialog.askopenfilenames(title="Seleziona files")
        for f in files:
            if f not in self._batch_listbox.get(0, "end"):
                self._batch_listbox.insert("end", f)
        if files and not self._batch_out_var.get():
            self._batch_out_var.set(str(Path(files[0]).parent))

    def _batch_clear(self):
        self._batch_listbox.delete(0, "end")

    def _browse_batch_out(self):
        p = filedialog.askdirectory(title="Cartella output batch")
        if p: self._batch_out_var.set(p)

    # ── Logica: crea ─────────────────────────────────────────────────────────

    def _do_create(self):
        src = self._create_file_var.get().strip()
        out = self._create_out_var.get().strip()
        if not src or not os.path.isfile(src):
            messagebox.showerror("Errore", "Seleziona un file valido."); return
        if not out:
            messagebox.showerror("Errore", "Seleziona una cartella di output."); return
        self._create_progress.start(12)
        t = threading.Thread(target=self._create_worker, args=(src, out), daemon=True)
        t.start()

    def _create_worker(self, src: str, out_dir: str):
        try:
            stem   = Path(src).stem
            tsq_p  = os.path.join(out_dir, stem + ".tsq")
            tsr_p  = os.path.join(out_dir, stem + ".tsr")
            info_p = os.path.join(out_dir, stem + "_timestamp_info.txt")

            self.log_info(f"Calcolo SHA-512 di {os.path.basename(src)} …")
            digest = sha512_file(src)
            self.log_info("Costruzione TSQ (RFC 3161, SHA-512) …")
            tsq_bytes = build_tsq(digest)
            with open(tsq_p, "wb") as fh:
                fh.write(tsq_bytes)
            self.log_info(f"TSQ salvato in: {tsq_p}")

            self.log_info("Invio richiesta a freetsa.org …")
            tsr_bytes = send_tsq(tsq_bytes)
            with open(tsr_p, "wb") as fh:
                fh.write(tsr_bytes)
            self.log_ok(f"TSR ricevuto e salvato in: {tsr_p}")

            # Riepilogo testuale
            info_lines = [
                "=" * 60,
                "MARCA TEMPORALE — FreeTSA.org",
                "=" * 60,
                f"File originale : {src}",
                f"Data richiesta : {datetime.now().isoformat()}",
                f"Algoritmo hash : SHA-512",
                f"Digest (hex)   : {digest.hex()}",
                f"File TSQ       : {tsq_p}",
                f"File TSR       : {tsr_p}",
                "",
            ]

            if openssl_available():
                self.log_info("Recupero informazioni TSR con openssl …")
                raw_info = tsr_info(tsr_p)
                info_lines += ["--- openssl ts -reply -text ---", raw_info, ""]

            with open(info_p, "w", encoding="utf-8") as fh:
                fh.write("\n".join(info_lines))
            self.log_ok(f"Riepilogo salvato in: {info_p}")
            self.log_ok("✔  Marca temporale creata con successo.")
            self.after(0, lambda: messagebox.showinfo(
                "Successo",
                f"Marca temporale creata!\n\nTSQ: {tsq_p}\nTSR: {tsr_p}\nInfo: {info_p}"
            ))
        except urllib.error.URLError as e:
            self.log_err(f"Errore di rete: {e}")
            self.after(0, lambda: messagebox.showerror("Errore di rete", str(e)))
        except Exception as e:
            self.log_err(f"Errore: {e}")
            self.after(0, lambda: messagebox.showerror("Errore", str(e)))
        finally:
            self.after(0, self._create_progress.stop)

    # ── Logica: verifica ─────────────────────────────────────────────────────

    def _do_verify(self):
        tsr = self._ver_tsr_var.get().strip()
        tsq = self._ver_tsq_var.get().strip()
        if not tsr or not os.path.isfile(tsr):
            messagebox.showerror("Errore", "Seleziona un file TSR valido."); return
        if not tsq or not os.path.isfile(tsq):
            messagebox.showerror("Errore", "Seleziona un file TSQ valido."); return
        if not openssl_available():
            messagebox.showwarning("openssl mancante",
                                   "openssl non trovato: la verifica non è disponibile.\n"
                                   "Installa openssl e aggiungilo al PATH."); return
        t = threading.Thread(target=self._verify_worker, args=(tsr, tsq), daemon=True)
        t.start()

    def _verify_worker(self, tsr: str, tsq: str):
        self.log_info("Download certificati FreeTSA (se necessario) …")
        try:
            ok, out = verify_tsr(tsr, tsq, self._certs_dir)
            self.log_info("--- Output openssl ---")
            for line in out.splitlines():
                self.log_ok(line) if ok else self.log_err(line)
            if ok:
                self.after(0, lambda: self._ver_result.config(
                    text="✔  Verifica: OK", fg=GREEN))
                self.after(0, lambda: messagebox.showinfo("Verifica", "✔  Verifica: OK"))
            else:
                self.after(0, lambda: self._ver_result.config(
                    text="✘  Verifica FALLITA", fg=RED))
                self.after(0, lambda: messagebox.showerror("Verifica", "✘  Verifica fallita.\n\n" + out))
        except Exception as e:
            self.log_err(str(e))
            self.after(0, lambda: messagebox.showerror("Errore", str(e)))

    def _do_info(self):
        tsr = self._ver_tsr_var.get().strip()
        if not tsr or not os.path.isfile(tsr):
            messagebox.showerror("Errore", "Seleziona un file TSR valido."); return
        if not openssl_available():
            messagebox.showwarning("openssl mancante", "openssl non trovato."); return
        info = tsr_info(tsr)
        self.log_info("--- Info TSR ---")
        for line in info.splitlines():
            self._log_write(line)
        # Mostra in una finestra separata
        win = tk.Toplevel(self)
        win.title("Informazioni TSR")
        win.configure(bg=BG)
        win.geometry("700x450")
        st = scrolledtext.ScrolledText(win, bg=PANEL, fg=TEXT, font=FONT_MONO,
                                       relief="flat", bd=8)
        st.pack(fill="both", expand=True, padx=12, pady=12)
        st.insert("end", info)
        st.configure(state="disabled")

    # ── Logica: batch ─────────────────────────────────────────────────────────

    def _do_batch(self):
        files = list(self._batch_listbox.get(0, "end"))
        out   = self._batch_out_var.get().strip()
        if not files:
            messagebox.showerror("Errore", "Aggiungi almeno un file."); return
        if not out:
            messagebox.showerror("Errore", "Seleziona una cartella di output."); return
        self._batch_progress["value"] = 0
        self._batch_progress["maximum"] = len(files)
        t = threading.Thread(target=self._batch_worker, args=(files, out), daemon=True)
        t.start()

    def _batch_worker(self, files: list, out_dir: str):
        ok_count = err_count = 0
        for i, src in enumerate(files, 1):
            self.log_info(f"[{i}/{len(files)}] Elaborazione: {os.path.basename(src)}")
            try:
                stem      = Path(src).stem
                tsq_bytes = build_tsq(sha512_file(src))
                tsq_p     = os.path.join(out_dir, stem + ".tsq")
                tsr_p     = os.path.join(out_dir, stem + ".tsr")
                with open(tsq_p, "wb") as fh: fh.write(tsq_bytes)
                tsr_bytes = send_tsq(tsq_bytes)
                with open(tsr_p, "wb") as fh: fh.write(tsr_bytes)
                self.log_ok(f"  ✔  {os.path.basename(src)} → {os.path.basename(tsr_p)}")
                ok_count += 1
            except Exception as e:
                self.log_err(f"  ✘  {os.path.basename(src)}: {e}")
                err_count += 1
            self.after(0, lambda v=i: self._batch_progress.__setitem__("value", v))
        self.log_ok(f"Batch completato: {ok_count} OK, {err_count} errori.")
        self.after(0, lambda: messagebox.showinfo(
            "Batch completato",
            f"File elaborati: {len(files)}\n✔ Successi: {ok_count}\n✘ Errori: {err_count}"
        ))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app = App()
    app.mainloop()
