import os
import time
import hashlib
import subprocess
import psutil


# ==========================
# SANDBOX SIMULATION ENGINE
# ==========================

def simulate_file_behavior(path):
    """
    Lightweight sandbox-style behavioral simulation.
    No real malware execution is performed.
    """

    start_time = time.time()

    result = {
        "file_executed": False,
        "process_spawned": False,
        "network_activity": False,
        "file_system_changes": [],
        "file_hash": None,
        "execution_time": 0,
        "behavior_score": 0
    }

    # ==========================
    # FILE HASH
    # ==========================
    try:
        with open(path, "rb") as f:
            file_data = f.read()
            result["file_hash"] = hashlib.sha256(file_data).hexdigest()
    except Exception:
        result["file_hash"] = None

    # ==========================
    # SAFE EXECUTION SIMULATION
    # ==========================
    try:
        proc = subprocess.Popen(
            ["echo", "sandbox_simulation"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        proc.communicate(timeout=2)
        result["file_executed"] = True
    except Exception:
        result["file_executed"] = False

    # ==========================
    # PROCESS MONITORING (HEURISTIC)
    # ==========================
    try:
        suspicious_processes = {
            "cmd.exe",
            "powershell.exe",
            "bash",
            "sh",
            "python.exe"
        }

        for proc in psutil.process_iter(["name"]):
            name = proc.info.get("name")
            if name and name.lower() in suspicious_processes:
                result["process_spawned"] = True
                break
    except Exception:
        result["process_spawned"] = False

    # ==========================
    # NETWORK ACTIVITY CHECK (HEURISTIC)
    # ==========================
    try:
        connections = psutil.net_connections()
        if len(connections) > 15:
            result["network_activity"] = True
    except Exception:
        result["network_activity"] = False

    # ==========================
    # FILE SYSTEM HEURISTICS
    # ==========================
    try:
        stat = os.stat(path)

        if stat.st_size > 5 * 1024 * 1024:
            result["file_system_changes"].append("large_file_detected")

        if time.time() - stat.st_mtime < 300:
            result["file_system_changes"].append("recently_modified")

    except Exception:
        pass

    # ==========================
    # BEHAVIOR SCORING ENGINE
    # ==========================

    score = 0

    if result["file_executed"]:
        score += 10

    if result["process_spawned"]:
        score += 25

    if result["network_activity"]:
        score += 30

    score += len(result["file_system_changes"]) * 10

    result["behavior_score"] = min(score, 100)
    result["execution_time"] = round(time.time() - start_time, 2)

    return result
