import json
from collections import Counter

LOG_FILE = "../cowrie/var/log/cowrie/cowrie.json"

ips = []
usernames = []
passwords = []
commands = []

with open(LOG_FILE, "r") as file:
    for line in file:
        event = json.loads(line)

        if event.get("eventid") == "cowrie.login.failed":
            ips.append(event.get("src_ip"))
            usernames.append(event.get("username"))
            passwords.append(event.get("password"))

        elif event.get("eventid") == "cowrie.command.input":
            commands.append(event.get("input"))

print("\n🔍 Honeypot Attack Analysis\n")

ip_counter = Counter(ips)

print("Top Attacker IPs:")
for ip, count in ip_counter.most_common(5):
    print(f"{ip} → {count} attempts")

if ip_counter and ip_counter.most_common(1)[0][1] > 10:
    print("\n⚠️ ALERT: Possible brute-force attack detected!")

print("\nMost Used Usernames:")
for user, count in Counter(usernames).most_common(5):
    print(f"{user} → {count}")

print("\nMost Used Passwords:")
for pwd, count in Counter(passwords).most_common(5):
    print(f"{pwd} → {count}")

print("\nCommands Executed:")
for cmd, count in Counter(commands).most_common(5):
    print(f"{cmd} → {count}")
