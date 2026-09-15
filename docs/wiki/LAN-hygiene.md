# LAN hygiene and home gateways

**v15.9.8** adds workstation LAN leak controls that work on **any** personal Windows 10/11 PC. Bastion **does not assume** a named ISP modem, mesh kit, or LAN address.

## What Apply does (section **LanHygiene**, off by default)

Enable it under main menu **4**, then **8 Apply**. Dry Run previews first.

| Control | Scope |
|---------|--------|
| LLMNR off | This Windows PC |
| WPAD autodetect override | This Windows PC |
| mDNS off | This Windows PC |
| NetBIOS-over-TCP off | IP-enabled adapters on this PC |
| Green Ethernet / GigaLite / EEE / Power Saving **Disabled** when those properties exist | Physical NICs that expose them |
| Outbound UDP 137 / 138 / 5353 block rules named `Bastion Block *` | Windows Firewall on this PC |

**Bastion never locks Speed & Duplex.** A 2.5 Gbps link on a long or marginal cable can retrain and look like disconnects; that is a cable/PHY choice, not a global Apply action.

## What Apply does **not** do

- Flash or log in to your ISP modem/router
- Assume a brand or LAN IP
- Turn off Wi-Fi on a mesh kit or unknown CPE
- Change VPN client features

## Recovery

Main menu **9 → 3 Network**

| Option | Meaning |
|--------|---------|
| **5** | Remove the Bastion outbound 137/138/5353 firewall rules only |
| **6** | Probe **this PC's IPv4 default gateway** over HTTP. If the banner matches a **Sagemcom Fast** GUI (some ISP skins), optional Wi-Fi-radio / UPnP / USB-SMB actions are offered after Yes. Any other CPE: identify only. **Password is never saved.** Most homes will not match. |

If option **6** says unknown or other-cpe, use the vendor admin page. Wrong firmware commands are out of scope.

## Controlled Folder Access / empty Protection History

Windows Security **Protection History** often stays blank for CFA blocks even when Event ID **1123** is in `Microsoft-Windows-Windows Defender/Operational`. Allow apps under **Virus & threat protection → Ransomware protection → Allow an app through Controlled folder access**. Defender Apply also refreshes ExtraCfaPaths that exist on this PC (Edge, PowerShell, and any other listed tools that are present). Do not turn CFA off only because History is empty.

## Side effects

Printers, NAS, Chromecast, and some Apple discovery can break. Reverse: Recovery **3 → 5**, then System Restore or re-enable discovery if you still need it.
