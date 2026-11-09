#!/usr/bin/env python3
"""Read-only native ELF MBA scan using Miasm and msynth."""
from __future__ import annotations
import argparse
import json
import re
import subprocess
import tempfile
import zipfile
from collections import Counter
from pathlib import Path

from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.expression.expression import ExprId, ExprInt, ExprOp, ExprSlice
from msynth import Simplifier

TARGET_LIBRARIES = (
    "libx.so", "libsatriyaid.so", "libsatriyaid2.so", "libstrxid.so", "libstub.so"
)
BITWISE_OPS = {"&", "|", "^", "~", "<<", ">>"}
ARITHMETIC_OPS = {"+", "-", "*"}
MAX_EXPR_NODES = 80

def read_function_symbols(path: Path):
    output = subprocess.run(
        ["readelf", "-Ws", str(path)], check=True,
        capture_output=True, text=True, errors="replace"
    ).stdout
    pattern = re.compile(
        r"^\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+FUNC\s+\S+\s+\S+\s+(\S+)\s+(.+?)\s*$"
    )
    found = {}
    for line in output.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        address, size, section, name = match.groups()
        address, size = int(address, 16), int(size)
        name = name.split("@", 1)[0]
        if address and size and section != "UND":
            found.setdefault(address, (address, size, name))
    return sorted(found.values())

def expression_stats(expr):
    ops = Counter()
    node_count = 0
    unsupported = False
    def visit(node):
        nonlocal node_count, unsupported
        node_count += 1
        if isinstance(node, ExprOp):
            ops[str(node.op)] += 1
        elif not isinstance(node, (ExprId, ExprInt, ExprSlice)):
            unsupported = True
        return node
    expr.visit(visit)
    return node_count, ops, unsupported

def is_mba_candidate(expr):
    nodes, ops, unsupported = expression_stats(expr)
    bitwise = sum(ops[op] for op in BITWISE_OPS)
    arithmetic = sum(ops[op] for op in ARITHMETIC_OPS)
    stats = {
        "nodes": nodes, "operators": dict(ops),
        "bitwise_ops": bitwise, "arithmetic_ops": arithmetic
    }
    return (
        not unsupported and 8 <= nodes <= MAX_EXPR_NODES
        and bitwise >= 2 and arithmetic >= 2
    ), stats

def analyze_library(path: Path, simplifier, max_functions: int, max_candidates: int):
    loc_db = LocationDB()
    with path.open("rb") as stream:
        container = Container.from_stream(stream, loc_db)
    if container.arch not in ("aarch64l", "aarch64b", "arml", "armb"):
        return {
            "library": path.name, "architecture": container.arch,
            "status": "skipped-unsupported-architecture", "candidates": []
        }

    machine = Machine(container.arch)
    disassembler = machine.dis_engine(container.bin_stream, loc_db=container.loc_db)
    lifter = machine.lifter_model_call(disassembler.loc_db)
    all_symbols = read_function_symbols(path)
    symbols = all_symbols[:max_functions]
    candidates, seen = [], set()
    failures = Counter()

    for address, _size, name in symbols:
        try:
            asm_cfg = disassembler.dis_multiblock(address)
            ir_cfg = lifter.new_ircfg_from_asmcfg(asm_cfg)
        except Exception as exc:
            failures[type(exc).__name__] += 1
            continue

        for ir_block in ir_cfg.blocks.values():
            for assign_block in ir_block:
                for source in assign_block.values():
                    try:
                        eligible, stats = is_mba_candidate(source)
                    except Exception:
                        continue
                    if not eligible:
                        continue
                    original = str(source)
                    if original in seen:
                        continue
                    seen.add(original)
                    record = {
                        "function": name, "address": hex(address),
                        "expression": original, **stats
                    }
                    try:
                        simplified = simplifier.simplify(source)
                        simplified_text = str(simplified)
                        new_nodes, _, new_unsupported = expression_stats(simplified)
                        smaller = (
                            not new_unsupported and simplified_text != original
                            and new_nodes < stats["nodes"]
                        )
                        record["verified_smaller_result"] = smaller
                        if smaller:
                            record["simplified_expression"] = simplified_text
                            record["simplified_nodes"] = new_nodes
                    except Exception as exc:
                        record["simplification_error"] = type(exc).__name__
                        failures["msynth:" + type(exc).__name__] += 1
                    candidates.append(record)
                    if len(candidates) >= max_candidates:
                        break
                if len(candidates) >= max_candidates:
                    break
            if len(candidates) >= max_candidates:
                break
        if len(candidates) >= max_candidates:
            break

    return {
        "library": path.name, "architecture": container.arch, "status": "analyzed",
        "function_symbols_found": len(all_symbols),
        "functions_examined": len(symbols),
        "mba_candidates": len(candidates),
        "verified_smaller_results": sum(
            1 for item in candidates if item.get("verified_smaller_result")
        ),
        "analysis_errors": dict(failures), "candidates": candidates
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("reports/msynth-native-scan.json"))
    parser.add_argument("--max-functions", type=int, default=120)
    parser.add_argument("--max-candidates", type=int, default=40)
    args = parser.parse_args()
    report = {
        "tool": "msynth",
        "scope": "read-only native ELF MBA expression scan",
        "apk": args.apk.name,
        "libraries": []
    }
    with tempfile.TemporaryDirectory(prefix="doge-msynth-") as temp_dir:
        temp_path = Path(temp_dir)
        with zipfile.ZipFile(args.apk) as apk:
            for library_name in TARGET_LIBRARIES:
                member = "lib/arm64-v8a/" + library_name
                try:
                    data = apk.read(member)
                except KeyError:
                    report["libraries"].append({
                        "library": library_name,
                        "status": "not-present-in-arm64-apk", "candidates": []
                    })
                    continue
                library_path = temp_path / library_name
                library_path.write_bytes(data)
                try:
                    print("[msynth] analyzing " + library_name, flush=True)
                    report["libraries"].append(
                        analyze_library(
                            library_path,
                            Simplifier(enforce_equivalence=True, solver_timeout=1000),
                            args.max_functions, args.max_candidates
                        )
                    )
                except Exception as exc:
                    report["libraries"].append({
                        "library": library_name, "status": "analysis-failed",
                        "error": type(exc).__name__ + ": " + str(exc),
                        "candidates": []
                    })
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({
        "output": str(args.output),
        "libraries_analyzed": sum(
            1 for item in report["libraries"] if item.get("status") == "analyzed"
        ),
        "mba_candidates": sum(item.get("mba_candidates", 0) for item in report["libraries"]),
        "verified_smaller_results": sum(
            item.get("verified_smaller_results", 0) for item in report["libraries"]
        )
    }, indent=2))

if __name__ == "__main__":
    main()
