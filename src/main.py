import json
import os
from datetime import datetime

def log(message: str):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}")

def load_goals():
    """Load goals.json in a BOM-safe way, regardless of encoding."""
    path = os.path.join(os.path.dirname(__file__), '..', 'goals.json')
    with open(path, 'rb') as f:
        raw = f.read()
    if raw[:3] == b'\xef\xbb\xbf':
        raw = raw[3:]
    elif raw[:2] == b'\xff\xfe':
        raw = raw[2:]
        raw = raw.decode('utf-16le').encode('utf-8')
    elif raw[:2] == b'\xfe\xff':
        raw = raw[2:]
        raw = raw.decode('utf-16be').encode('utf-8')
    return json.loads(raw.decode('utf-8'))

def run_goal(goal):
    log(f"Running goal: {goal}")
    # Implement goal execution logic here

def main():
    log("=== Autonomous Loop Start ===")
    try:
        goals = load_goals()
    except Exception as e:
        log(f"Failed to load goals.json: {e}")
        return
    if not goals:
        log("No goals in queue. Exiting.")
        return
    for goal in goals:
        run_goal(goal)
    log("=== Autonomous Loop Complete ===")

if __name__ == "__main__":
    main()
