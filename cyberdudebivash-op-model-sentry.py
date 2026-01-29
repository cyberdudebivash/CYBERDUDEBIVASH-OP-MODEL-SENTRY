#!/usr/bin/env python3
"""
CYBERDUDEBIVASH® OP-MODEL-SENTRY – Premium Enterprise Edition v2.4
Purpose: Zero-trust deep pickle analysis for PyTorch .pth/.pt files
         with torch-safe state_dict inspection & nested bytes disassembly

Version: 2.4.0 (License via env vars + all detection enhancements)
License: CYBERDUDEBIVASH ENTERPRISE LICENSE – Paid Only

Copyright © 2026 CyberDudeBivash Pvt. Ltd. – Bhubaneswar, Odisha, India
All rights reserved. Unauthorized distribution or modification prohibited.
"""

import sys
import argparse
import pickletools
import re
import json
import logging
import os
import hashlib
import uuid
import datetime
import platform
import getpass
from pathlib import Path
from typing import Dict, List
from rich.console import Console
from rich.table import Table
from rich import print as rprint
import yaml
import torch

# Zero-Trust Secure Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler("op-model-sentry.log"), logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("op-model-sentry")

console = Console()

MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024 * 1024
ALLOWED_EXTENSIONS = {'.pth', '.pt', '.pkl'}

HIGH_RISK_OPCODES = {
    'GLOBAL', 'REDUCE', 'BUILD', 'INST', 'NEWOBJ', 'OBJ', 'EXEC', 'EVAL',
    'MEMOIZE', 'PUT', 'GET', 'BINUNICODE', 'SHORT_BINUNICODE'
}

DANGEROUS_PATTERNS = [
    r'os\.system', r'subprocess\.', r'exec\(', r'eval\(', r'__import__',
    r'socket\.', r'requests\.', r'urllib\.', r'curl', r'wget', r'base64\.b64decode'
]

TORCH_HIGH_RISK_PATTERNS = [
    r'_rebuild_tensor', r'_rebuild_parameter', r'_rebuild_tensor_v2'
]

# ────────────────────────────────────────────────
# LICENSE KEY VALIDATION – Configured via env vars
# ────────────────────────────────────────────────
def get_hardware_id():
    mac = uuid.getnode()
    cpu = platform.processor()
    user = getpass.getuser()
    combined = f"{mac}{cpu}{user}"
    return hashlib.sha256(combined.encode()).hexdigest()[:16].upper()

def check_license():
    """
    Offline license validation using environment variables
    - LICENSE_KEY: CYBER-YYYY-XXXX-YYYY-ZZZZ
    - EXPIRY_DATE: YYYY-MM-DD (string)
    - HARDWARE_HASH: 16-char uppercase hex (optional)
    """
    LICENSE_KEY = os.getenv("CYBERDUDEBIVASH_LICENSE_KEY")
    EXPIRY_STR = os.getenv("CYBERDUDEBIVASH_EXPIRY_DATE")
    ALLOWED_HASH = os.getenv("CYBERDUDEBIVASH_HARDWARE_HASH")

    if not LICENSE_KEY:
        print("[ERROR] CYBERDUDEBIVASH_LICENSE_KEY environment variable not set.")
        print("       Contact iambivash@cyberdudebivash.com for license.")
        sys.exit(1)

    if not re.match(r'^CYBER-\d{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$', LICENSE_KEY):
        print("[ERROR] Invalid license key format.")
        sys.exit(1)

    # Expiry check
    try:
        expiry_date = datetime.datetime.strptime(EXPIRY_STR, "%Y-%m-%d").date() if EXPIRY_STR else None
        if expiry_date and datetime.date.today() > expiry_date:
            print(f"[ERROR] License expired on {expiry_date}. Contact support for renewal.")
            sys.exit(1)
    except:
        print("[ERROR] Invalid expiry date format (expected YYYY-MM-DD).")
        sys.exit(1)

    # Hardware binding (optional – skip if not set)
    if ALLOWED_HASH:
        current_hash = get_hardware_id()
        if current_hash != ALLOWED_HASH:
            print("[ERROR] Hardware mismatch. License not valid on this machine.")
            print("       Contact support to re-bind.")
            sys.exit(1)

    print("[INFO] License validated successfully.")
    if expiry_date:
        print(f"[INFO] Valid until {expiry_date}")
    else:
        print("[INFO] No expiry configured (perpetual license)")

def disassemble_bytes(data: bytes) -> List[str]:
    lines = []
    try:
        for opcode, arg, pos in pickletools.genops(data):
            lines.append(f"{opcode} {arg if arg is not None else ''}")
    except Exception as e:
        lines.append(f"Disassembly error: {str(e)}")
    return lines

def deep_scan_state_dict(state_dict: Dict) -> List[str]:
    findings = []
    for key, value in state_dict.items():
        if isinstance(value, bytes):
            if value.startswith(b'\x80'):
                findings.append(f"Pickle bytes detected in key '{key}' – potential hidden exploit")
                self.risk_score += 20

                dis_lines = disassemble_bytes(value)
                text = ' '.join(dis_lines).upper()
                for op in HIGH_RISK_OPCODES:
                    if op in text:
                        line_context = next((line for line in dis_lines if op in line), "")
                        findings.append(f"High-risk opcode in bytes value '{key}': {op} (line: {line_context})")
                        self.risk_score += 40
                for pattern in DANGEROUS_PATTERNS:
                    if re.search(pattern, text, re.IGNORECASE):
                        findings.append(f"Dangerous pattern in bytes value '{key}': {pattern}")
                        self.risk_score += 30
        if isinstance(value, str):
            text = value.upper()
            for pattern in DANGEROUS_PATTERNS:
                if re.search(pattern, text):
                    findings.append(f"Dangerous pattern in string value '{key}': {pattern}")
                    self.risk_score += 30
        if isinstance(value, dict):
            findings.extend(deep_scan_state_dict(value))
        if isinstance(value, (list, tuple)):
            for item in value:
                if isinstance(item, dict):
                    findings.extend(deep_scan_state_dict(item))
                if isinstance(item, (bytes, str)):
                    text = str(item).upper()
                    for pattern in DANGEROUS_PATTERNS:
                        if re.search(pattern, text):
                            findings.append(f"Dangerous pattern in nested item '{key}': {pattern}")
                            self.risk_score += 30
    return findings

class ModelSentry:
    def __init__(self, custom_rules_path: str = None):
        self.custom_rules = self.load_custom_rules(custom_rules_path)
        self.risk_score = 0

    def load_custom_rules(self, path):
        if path and Path(path).exists():
            try:
                with open(path, 'r') as f:
                    return yaml.safe_load(f) or {}
            except Exception as e:
                logger.error(f"Failed to load custom rules: {e}")
        return {}

    def validate_file(self, filepath: Path) -> Dict:
        result = {"valid": False, "error": None}
        if not filepath.exists():
            result["error"] = f"File not found: {filepath}"
            logger.error(result["error"])
            return result
        if filepath.suffix.lower() not in ALLOWED_EXTENSIONS:
            result["error"] = f"Invalid file type: {filepath} (only .pth/.pt/.pkl allowed)"
            logger.warning(result["error"])
            return result
        try:
            file_size = filepath.stat().st_size
            if file_size > MAX_FILE_SIZE_BYTES:
                result["error"] = f"File too large (>2GB): {filepath} ({file_size / 1024 / 1024:.2f} MB)"
                logger.warning(result["error"])
                return result
        except Exception as e:
            result["error"] = f"Cannot access file: {str(e)}"
            logger.error(result["error"])
            return result
        result["valid"] = True
        logger.info(f"Valid file: {filepath} ({file_size / 1024 / 1024:.2f} MB)")
        return result

    def extract_metadata_safe(self, filepath: Path) -> Dict:
        try:
            model = torch.load(str(filepath), map_location='cpu', weights_only=True)
            metadata = {
                "model_type": str(type(model).__name__),
                "num_parameters": sum(p.numel() for p in model.parameters()) if hasattr(model, 'parameters') else "N/A",
                "layers": len(list(model.children())) if hasattr(model, 'children') else "N/A",
                "safe_load_success": True
            }
            return metadata
        except Exception as e:
            logger.debug(f"Safe metadata extraction failed: {e}")
            return {"safe_load_success": False, "error": str(e)}

    def deep_scan_state_dict(self, state_dict: Dict) -> List[str]:
        findings = []
        for key, value in state_dict.items():
            if isinstance(value, bytes):
                if value.startswith(b'\x80'):
                    findings.append(f"Pickle bytes detected in key '{key}' – potential hidden exploit")
                    self.risk_score += 20

                    dis_lines = disassemble_bytes(value)
                    text = ' '.join(dis_lines).upper()
                    for op in HIGH_RISK_OPCODES:
                        if op in text:
                            line_context = next((line for line in dis_lines if op in line), "")
                            findings.append(f"High-risk opcode in bytes value '{key}': {op} (line: {line_context})")
                            self.risk_score += 40
                    for pattern in DANGEROUS_PATTERNS:
                        if re.search(pattern, text, re.IGNORECASE):
                            findings.append(f"Dangerous pattern in bytes value '{key}': {pattern}")
                            self.risk_score += 30
            if isinstance(value, str):
                text = value.upper()
                for pattern in DANGEROUS_PATTERNS:
                    if re.search(pattern, text):
                        findings.append(f"Dangerous pattern in string value '{key}': {pattern}")
                        self.risk_score += 30
            if isinstance(value, dict):
                findings.extend(self.deep_scan_state_dict(value))
            if isinstance(value, (list, tuple)):
                for item in value:
                    if isinstance(item, dict):
                        findings.extend(self.deep_scan_state_dict(item))
                    if isinstance(item, (bytes, str)):
                        text = str(item).upper()
                        for pattern in DANGEROUS_PATTERNS:
                            if re.search(pattern, text):
                                findings.append(f"Dangerous pattern in nested item '{key}': {pattern}")
                                self.risk_score += 30
        return findings

    def analyze_file(self, filepath: Path) -> Dict:
        validation = self.validate_file(filepath)
        if not validation["valid"]:
            return {"file": str(filepath), "error": validation["error"], "risk": 0, "metadata": {}}

        metadata = self.extract_metadata_safe(filepath)

        try:
            state_dict = torch.load(str(filepath), map_location='cpu', weights_only=True)
        except Exception as e:
            return {"file": str(filepath), "error": f"Load failed: {str(e)}", "risk": 0, "metadata": metadata}

        self.risk_score = 0
        findings = []

        state_findings = self.deep_scan_state_dict(state_dict)
        findings.extend(state_findings)
        self.risk_score += len(state_findings) * 30

        state_str = str(state_dict).upper()
        for pattern in TORCH_HIGH_RISK_PATTERNS:
            if pattern.upper() in state_str:
                findings.append(f"Torch reducer pattern: {pattern}")
                self.risk_score += 15

        risk_level = "CRITICAL" if self.risk_score >= 70 else "HIGH" if self.risk_score >= 40 else "MEDIUM" if self.risk_score >= 20 else "LOW"

        return {
            "file": str(filepath),
            "risk_score": self.risk_score,
            "risk_level": risk_level,
            "findings": findings,
            "metadata": metadata,
            "safe_to_load": self.risk_score < 20
        }

def main():
    check_license()  # License check first

    parser = argparse.ArgumentParser(description="CYBERDUDEBIVASH® OP-MODEL-SENTRY – Premium Enterprise PyTorch Scanner")
    parser.add_argument("path", nargs="?", help="Single .pth/.pt file")
    parser.add_argument("--dir", help="Scan directory")
    parser.add_argument("--recursive", "-r", action="store_true")
    parser.add_argument("--rules", help="Custom rules YAML file")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    if not args.path and not args.dir:
        parser.print_help()
        sys.exit(1)

    sentry = ModelSentry(args.rules)

    files = []
    if args.path:
        files = [Path(args.path)]
    else:
        path = Path(args.dir)
        pattern = "**/*" if args.recursive else "*"
        files = list(path.glob(pattern))

    results = []
    table = Table(title="OP-MODEL-SENTRY Scan Results")
    table.add_column("File", style="cyan")
    table.add_column("Risk Score", style="magenta")
    table.add_column("Risk Level", style="bold")
    table.add_column("Findings", style="yellow")
    table.add_column("Metadata", style="green")

    for file_path in files:
        result = sentry.analyze_file(file_path)
        results.append(result)

        if args.json:
            continue

        row_color = "red" if result.get("risk_level") in ["CRITICAL", "HIGH"] else "green"
        metadata_str = json.dumps(result.get("metadata", {}), indent=None)[:100] + "..." if result.get("metadata") else "N/A"
        table.add_row(
            str(file_path),
            str(result.get("risk_score", 0)),
            result.get("risk_level", "UNKNOWN"),
            ", ".join(result.get("findings", ["None"])) or "None",
            metadata_str,
            style=row_color
        )

    if not args.json:
        rprint(table)

    if args.json:
        print(json.dumps(results, indent=2))

    critical = sum(1 for r in results if r.get("risk_level") in ["CRITICAL", "HIGH"])
    console.print(f"\n[bold]Scan Complete:[/] {len(results)} files | {critical} high-risk")

if __name__ == "__main__":
    main()