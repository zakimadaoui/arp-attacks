
## ⚠️ Disclaimer & Intended Use ⚠️

This project is provided strictly for educational and research purposes only.

It is intended to help students, developers, and security researchers understand how the ARP protocol works, how ARP spoofing/poisoning attacks are performed, and—most importantly—how such attacks can be detected and mitigated in real systems.

Unauthorized use of this software against networks, systems, or devices that you do not own or do not have explicit permission to test is illegal and unethical.

By using this software, you agree that:
- You will only use it on systems you own or have explicit, written permission to test.
- You understand that ARP spoofing can disrupt networks, compromise privacy, and cause damage if misused.
- You take full responsibility for any actions performed using this software.

The author(s) of this project:

- Do not condone or support malicious activity
- Assume no liability for any misuse, damage, data loss, or legal consequences resulting from the use of this software

## Host Dependencies for C++ build
```
sudo apt install libpcap-dev
```

## Build/Run instructions

```bash
# builds and runs the rust version
make rs
# builds and runs the C++ version
make cpp
```