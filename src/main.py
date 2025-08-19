import os
import json
import subprocess
from datetime import datetime
import requests

GOALS_FILE = os.path.join(os.path.dirname(__file__), '..', 'goals.json')
LOG_FILE = os.path.join(os.path.dirname(__file__), '..', 'activity.log')
CLAUDE_API_KEY = os.environ.get("CLAUDE_API_KEY")  # Set in your env

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

def call_claude(prompt):
    url = "https://api.anthropic.com/v1/messages"
    headers = {
        "x-api-key": CLAUDE_API_KEY,
        "Content-Type": "application/json",
        "anthropic-version": "2023-06-01"
    }
    body = {
        "model": "claude-3-5-sonnet-latest",
        "max_tokens": 800,
        "messages": [{"role": "user", "content": prompt}]
    }
    response = requests.post(url, headers=headers, json=body)
    response.raise_for_status()
    data = response.json()
    return data["content"][0]["text"]

def run_goal(goal):
    log(f"Processing goal: {goal}")
    prompt = f"Write Python code to accomplish this goal:\n{goal}"
    code = call_claude(prompt)
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
