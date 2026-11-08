# Threat Actors

## Insider
- Capability: holds a valid account, knows the message format from PROTOCOL.md, can run the client and send to any online user.
- Motivation: curiosity, grudge, or a grade advantage over teammates.
- Entry points: S5 (login tries), S10 (message flooding), S11 (escape codes in messages), S12 (duplicate-login check), S13 (bad ciphertext).
- Likely impact: C low (only sees messages sent to them), I low (the server sets the sender name, but display can be altered via S11), A medium (S10 flooding can slow the server).

## Cybercriminal
- Capability: scans open ports with Nmap, runs password guessing scripts, and cracks hashes with Hashcat or John if they get users.txt.
- Motivation: stolen credentials to reuse on other accounts or to sell.
- Entry points: S1 (exposed port), S5 (online guessing), S7 (free registration), S8 (username enumeration), S9 (credential file and fast hash).
- Likely impact: C high (passwords recovered offline through S9), I medium (account takeover after cracking), A low.

## Network Attacker
- Capability: on the same LAN, uses ARP spoofing and Wireshark to sit between client and server.
- Motivation: capture passwords and messages from users on the same network.
- Entry points: S2 (unauthenticated DH from client), S3 (unsigned DH from server).

- Likely impact: C high (reads all traffic after the key exchange it intercepts), I high (can change messages in transit, since the baseline has no authentication), A low.
