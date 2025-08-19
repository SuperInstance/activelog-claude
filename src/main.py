import os
import json
import subprocess
from datetime import datetime

GOALS_FILE = os.path.join(os.path.dirname(__file__), '..', 'goals.json')
LOG_FILE = os.path.join(os.path.dirname(__file__), '..', 'activity.log')

def log(message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(LOG_FILE, 'a', encoding='utf-8') as logf:
        logf.write(f"[{timestamp}] {message}\n")
    print(f"[{timestamp}] {message}")

def load_goals():
    if os.path.exists(GOALS_FILE):
        with open(GOALS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def run_goal(goal):
    log(f"Processing goal: {goal}")
    # TODO: Replace with actual Claude model call to generate code
    code = f"print('Goal executed: {goal}')"
    code_file = os.path.join(os.path.dirname(__file__), 'generated_task.py')
    with open(code_file, 'w', encoding='utf-8') as cf:
        cf.write(code)
    log(f"Generated code file: {code_file}")
    subprocess.run(["python", code_file], check=True)

def main():
    log("=== Autonomous Loop Start ===")
    goals = load_goals()
    if not goals:
        log("No goals in queue. Exiting.")
        return
    for goal in goals:
        run_goal(goal)
    log("=== Autonomous Loop Complete ===")

if __name__ == "__main__":
    main()
