
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
sudo apt install libpcap-dev bison flex
```

## Build/Run instructions

```bash
# only for the first time
make init

# builds and runs the rust version
make rs
# builds and runs the C++ version
make cpp
```

## Example output
```
make cpp
1: wlp0s20f3
        ether: xx:xx:xx:xx:xx:xx
         inet: 192.168.50.7
        inet6: fe80::49ab:b234:87e7:9b82
2: lo
        ether: 00:00:00:00:00:00
         inet: 127.0.0.1
        inet6: ::1
choose a network interface:
1
selected: wlp0s20f3
Scanning network. Press ENTER to stop
0: zak-pc              192.168.50.7    xx:xx:xx:xx:xx:xx 
1: RT-AX68U-5420       192.168.50.1    xx:xx:xx:xx:xx:xx 
2: zak-hp              192.168.50.27   xx:xx:xx:xx:xx:xx 
3: OnePlus-11-5G       192.168.50.99   xx:xx:xx:xx:xx:xx 
 
Select victim:
3
Select router:
1
selected:
victim: OnePlus-11-5G       192.168.50.99   xx:xx:xx:xx:xx:xx 
router: RT-AX68U-5420       192.168.50.1    xx:xx:xx:xx:xx:xx
select attack: dos, mitm
mitm
Starting Man-In-The-Middle attack... use Ctrl+C to cancel
Found SNI: github.com
Found SNI: avatars.githubusercontent.com
Found SNI: api.github.com
Found SNI: avatars.githubusercontent.com
Found SNI: collector.github.com
Found SNI: collector.github.com
Found SNI: collector.github.com
Found SNI: collector.github.com
```