import os
import sys

def run_delta(current_file, state_dir, output_new_file):
    if not os.path.exists(current_file):
        print(f"[-] Current assets file does not exist: {current_file}")
        return 0

    os.makedirs(state_dir, exist_ok=True)
    known_file = os.path.join(state_dir, "known_subdomains.txt")

    current_assets = set()
    with open(current_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            item = line.strip().lower()
            if item:
                # remove any leading protocol or trailing slashes
                item = item.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
                if item:
                    current_assets.add(item)

    known_assets = set()
    if os.path.exists(known_file):
        with open(known_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                item = line.strip().lower()
                if item:
                    known_assets.add(item)

    new_assets = current_assets - known_assets

    os.makedirs(os.path.dirname(output_new_file), exist_ok=True)
    with open(output_new_file, "w", encoding="utf-8") as f:
        for a in sorted(new_assets):
            f.write(f"{a}\n")

    # Update known database with newly seen assets
    if new_assets:
        with open(known_file, "a", encoding="utf-8") as f:
            for a in sorted(new_assets):
                f.write(f"{a}\n")

    print(f"[*] Delta Tracker: {len(current_assets)} total found | {len(known_assets)} previously known | {len(new_assets)} NEW assets.")
    if new_assets:
        print(f"[🔥] DELTA ALERT: Detected {len(new_assets)} brand-new assets never seen before!")
    return len(new_assets)

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python delta_tracker.py <current_assets_file> <state_dir> <output_new_file>")
        sys.exit(1)
    run_delta(sys.argv[1], sys.argv[2], sys.argv[3])
