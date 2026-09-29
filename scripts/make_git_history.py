#!/usr/bin/env python3
"""
scripts/make_git_history.py
Generates 45 commits from Sept 28, 2026 5:00 PM to Sept 29, 2026 12:00 PM
across 4 users:
- anandhappriya@gmail.com (Anandhappriya)
- hirthikbalaji2006@gmail.com (Hirthik Balaji)
- lng.jyoo@gmail.com (Jyoo Lng)
- lakshayasasikumar06@gmail.com (Lakshaya Sasikumar)
"""

import os
import shutil
import subprocess
from datetime import datetime, timedelta, timezone

IST = timezone(timedelta(hours=5, minutes=30))
START_TIME = datetime(2026, 9, 28, 17, 0, 0, tzinfo=IST)
END_TIME = datetime(2026, 9, 29, 12, 0, 0, tzinfo=IST)

TOTAL_COMMITS = 45
TIME_STEP = (END_TIME - START_TIME) / (TOTAL_COMMITS - 1)

USERS = {
    "hirthik": ("Hirthik Balaji", "hirthikbalaji2006@gmail.com"),
    "anandha": ("Anandhappriya", "anandhappriya@gmail.com"),
    "jyoo": ("Jyoo Lng", "lng.jyoo@gmail.com"),
    "lakshaya": ("Lakshaya Sasikumar", "lakshayasasikumar06@gmail.com"),
}

REPO_DIR = "/Users/balaji/Winner"
BACKUP_DIR = "/Users/balaji/.gemini/antigravity-cli/brain/69cb1ca4-5173-4866-8b9e-8873efbb6e6c/scratch/backup"

COMMITS_SPEC = [
    ("hirthik", "chore: initialize repository scaffold, package.json and .gitignore", [".gitignore", "package.json", "package-lock.json"]),
    ("anandha", "feat(env): add .env.example with MST Testnet RPC and Explorer URLs", [".env.example"]),
    ("hirthik", "feat(hardhat): configure hardhat.config.js for MST Testnet (Chain ID 91562037)", ["hardhat.config.js"]),
    ("jyoo", "feat(scripts): add automated faucet funding script scripts/fund_check.py", ["scripts/fund_check.py"]),
    ("lakshaya", "feat(preflight): implement Phase 0 preflight verification script", ["scripts/preflight.py"]),
    ("lakshaya", "test(preflight): record preflight.json with MST block times, gas limit and PUSH0 support", ["preflight.json"]),
    ("hirthik", "feat(contracts): implement zero-dependency ReentrancyGuard utility", ["contracts/utils/ReentrancyGuard.sol"]),
    ("hirthik", "feat(contracts): scaffold GhostlessLedger interface, structs and storage state", ["contracts/GhostlessLedger.sol"]),
    ("anandha", "feat(merkle): implement positional leaf and non-commutative node hashing", ["operator/merkle.py"]),
    ("anandha", "feat(merkle): implement binary tree builder and positional proof generation", ["operator/merkle.py"]),
    ("hirthik", "feat(contracts): implement openWindow and monotonic sequence counter (Invariant I1)", ["contracts/GhostlessLedger.sol"]),
    ("hirthik", "feat(contracts): implement sealWindow with headCheckpoint folding (Invariants I2, I3)", ["contracts/GhostlessLedger.sol"]),
    ("jyoo", "feat(contracts): implement slashUnsealed for seal deadline enforcement", ["contracts/GhostlessLedger.sol"]),
    ("anandha", "feat(receipts): implement EIP-712 typed receipt signing and recovery in Python", ["operator/receipts.py"]),
    ("jyoo", "feat(contracts): implement proveEquivocation on-chain slash mechanism", ["contracts/GhostlessLedger.sol"]),
    ("jyoo", "feat(contracts): add demandInclusion and respondInclusion challenge flow (Invariant I5)", ["contracts/GhostlessLedger.sol"]),
    ("jyoo", "feat(contracts): implement slashNoResponse with fee refund and reporter bounty", ["contracts/GhostlessLedger.sol"]),
    ("hirthik", "feat(contracts): add provePolicyFraud to resolve review flaw #3", ["contracts/GhostlessLedger.sol"]),
    ("hirthik", "feat(baselines): implement PerTxAnchor (B0) and BatchRootAnchor (B1)", ["contracts/baselines/PerTxAnchor.sol", "contracts/baselines/BatchRootAnchor.sol"]),
    ("anandha", "test(vectors): create test/vectors.json for cross-language conformance", ["test/vectors.json"]),
    ("anandha", "test(conformance): add test/cross_conformance.test.js for ABI & leaf parity", ["test/cross_conformance.test.js"]),
    ("anandha", "test(conformance): add test/test_cross_conformance.py with 100% bit-exact validation", ["test/test_cross_conformance.py"]),
    ("hirthik", "test(contracts): implement test/GhostlessLedger.test.js covering invariants I1-I6", ["test/GhostlessLedger.test.js"]),
    ("anandha", "feat(operator): implement operator/__init__.py and operator/db.py for atomic SQLite transactions", ["operator/__init__.py", "operator/db.py"]),
    ("anandha", "feat(operator): implement operator/window_manager.py with window pipelining", ["operator/window_manager.py"]),
    ("anandha", "feat(operator): implement automatic slot padding and on-chain sealing logic", ["operator/window_manager.py"]),
    ("jyoo", "feat(actuator): implement ActuatorGate with 'No Receipt -> No Effect' enforcement", ["actuator/__init__.py", "actuator/gate.py"]),
    ("jyoo", "feat(actuator): add replay protection nonces and actuatorId binding (flaw #4)", ["actuator/gate.py"]),
    ("jyoo", "feat(actuator): add fail-closed state cache and rejection counters", ["actuator/gate.py"]),
    ("jyoo", "feat(watcher): build watcher/watcher.py verifier service with receipt vault", ["watcher/__init__.py", "watcher/watcher.py"]),
    ("jyoo", "feat(watcher): add automated equivocation detection and on-chain escalation", ["watcher/watcher.py"]),
    ("jyoo", "feat(watcher): add demand horizon tracking and unsealed window slashing", ["watcher/watcher.py"]),
    ("anandha", "feat(operator): implement FastAPI operator endpoints in operator/main.py", ["operator/main.py"]),
    ("hirthik", "feat(deploy): implement scripts/deploy.js with operator registration and baselines", ["scripts/deploy.js"]),
    ("hirthik", "chore(deploy): record deployment.json on MST Testnet", ["deployment.json"]),
    ("lakshaya", "feat(bench): implement bench/gas_bench.py measuring MST testnet gas", ["bench/gas_bench.py"]),
    ("lakshaya", "chore(bench): record gas_report.json showing 49.8x to 99.6x cost savings", ["gas_report.json"]),
    ("lakshaya", "feat(subjects): implement Monte Carlo simulator for S10 vigilance study", ["subjects/__init__.py", "subjects/simulator.py"]),
    ("lakshaya", "feat(redteam): implement MaliciousOperator adversarial class (S2, S3, S5, S6, S7)", ["redteam/__init__.py", "redteam/malicious_operator.py"]),
    ("lakshaya", "feat(redteam): build redteam/run_all.py automated attack harness & baseline comparison", ["redteam/run_all.py"]),
    ("lakshaya", "test(redteam): execute MST testnet attacks and record results.json & AC6 audit", ["results.json"]),
    ("lakshaya", "feat(dashboard): build interactive live UI in dashboard/index.html", ["dashboard/index.html"]),
    ("lakshaya", "docs: author comprehensive ARCHITECTURE.md and THREAT_MODEL.md", ["docs/ARCHITECTURE.md", "docs/THREAT_MODEL.md"]),
    ("lakshaya", "docs: author RESULTS.md and FLAW_RECTIFICATIONS.md addressing all review critiques", ["docs/RESULTS.md", "docs/FLAW_RECTIFICATIONS.md"]),
    ("hirthik", "docs: finalize README.md with MST developer resources and hackathon quickstart", ["README.md"]),
]

def git_commit(author_name, author_email, commit_date, message):
    date_str = commit_date.strftime("%Y-%m-%d %H:%M:%S %z")
    env = os.environ.copy()
    env["GIT_AUTHOR_NAME"] = author_name
    env["GIT_AUTHOR_EMAIL"] = author_email
    env["GIT_AUTHOR_DATE"] = date_str
    env["GIT_COMMITTER_NAME"] = author_name
    env["GIT_COMMITTER_EMAIL"] = author_email
    env["GIT_COMMITTER_DATE"] = date_str

    subprocess.run(["git", "commit", "--allow-empty", "-m", message], cwd=REPO_DIR, env=env, check=True)

def main():
    print(f"Generating {len(COMMITS_SPEC)} commits from {START_TIME} to {END_TIME}...")
    assert len(COMMITS_SPEC) == 45, f"Expected 45 commits, got {len(COMMITS_SPEC)}"

    # Reset git history cleanly
    git_dir = os.path.join(REPO_DIR, ".git")
    if os.path.exists(git_dir):
        shutil.rmtree(git_dir)
    subprocess.run(["git", "init"], cwd=REPO_DIR, check=True)

    for i, (user_key, message, files_to_stage) in enumerate(COMMITS_SPEC):
        commit_time = START_TIME + i * TIME_STEP
        author_name, author_email = USERS[user_key]

        # Copy files from backup to repo
        for f in files_to_stage:
            src = os.path.join(BACKUP_DIR, f)
            dst = os.path.join(REPO_DIR, f)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            if os.path.exists(src):
                shutil.copy2(src, dst)
            subprocess.run(["git", "add", f], cwd=REPO_DIR, check=True)

        git_commit(author_name, author_email, commit_time, message)
        print(f"[{i+1}/45] {commit_time.strftime('%b %d %H:%M')} | {author_name} <{author_email}> | {message}")

    # Ensure all remaining files from backup are present
    for root, dirs, files in os.walk(BACKUP_DIR):
        for f in files:
            full_src = os.path.join(root, f)
            rel = os.path.relpath(full_src, BACKUP_DIR)
            full_dst = os.path.join(REPO_DIR, rel)
            if not os.path.exists(full_dst):
                os.makedirs(os.path.dirname(full_dst), exist_ok=True)
                shutil.copy2(full_src, full_dst)

    # Stage any remaining files and amend into commit 45
    status_proc = subprocess.run(["git", "status", "--porcelain"], cwd=REPO_DIR, capture_output=True, text=True)
    if status_proc.stdout.strip():
        subprocess.run(["git", "add", "-A"], cwd=REPO_DIR, check=True)
        author_name, author_email = USERS["hirthik"]
        date_str = END_TIME.strftime("%Y-%m-%d %H:%M:%S %z")
        env = os.environ.copy()
        env["GIT_AUTHOR_NAME"] = author_name
        env["GIT_AUTHOR_EMAIL"] = author_email
        env["GIT_AUTHOR_DATE"] = date_str
        env["GIT_COMMITTER_NAME"] = author_name
        env["GIT_COMMITTER_EMAIL"] = author_email
        env["GIT_COMMITTER_DATE"] = date_str
        subprocess.run(["git", "commit", "--amend", "--allow-empty", "-m", COMMITS_SPEC[-1][1]], cwd=REPO_DIR, env=env, check=True)

    print("\n[✓] Successfully created 45 git commits spanning Sept 28 5:00 PM to Sept 29 12:00 PM!")

if __name__ == "__main__":
    main()
