import os
import json
from datetime import datetime

def main():
    print(f"[{datetime.now()}] Starting autonomous loop...")

    # Load goals
    goals_path = os.path.join(os.path.dirname(__file__), '..', 'goals.json')
    if os.path.exists(goals_path):
        with open(goals_path, 'r') as f:
            goals = json.load(f)
        print(f"Loaded {len(goals)} goals from goals.json")
    else:
        print("No goals.json found — create one to feed the loop.")

    # TODO: insert model call + code generation logic here

if __name__ == "__main__":
    main()
