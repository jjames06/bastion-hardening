# LAN hygiene and home gateways

**v15.9.8** adds workstation LAN leak controls that work on **any** personal Windows 10/11 PC. Bastion **does not assume** a named ISP modem, mesh kit, or LAN address.

## What Apply does (section **LanHygiene**, off by default)

Enable it under main menu **4**, then **8 Apply**. Dry Run previews first.

| Control | Scope |
|---------|--------|
| LLMNR off | The Windows PC running Bastion |
| WPAD autodetect override | The Windows PC running Bastion |
| mDNS off | The Windows PC running Bastion |
| NetBIOS-over-TCP off | IP-enabled adapters on that PC |
| Green Ethernet / GigaLite / EEE / Power Saving **Disabled** when those properties exist | Physical NICs that expose them |
| Outbound UDP 137 / 138 / 5353 block rules named `Bastion Block *` | Windows Firewall on that PC |

Apply does **not** lock NIC speed. Speed is a cable and adapter choice, not a Bastion control.

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
| **6** | Probe the IPv4 default gateway of the computer running Bastion over HTTP. If the admin speaks a known JSON gateway protocol, optional Wi-Fi-radio / UPnP / USB-SMB actions are offered after Yes. Any other CPE: identify only. **Password is never saved.** Most homes will not match. |

If option **6** says unknown or other-cpe, use the vendor admin page. Bastion will not send commands to a consumer router UI it does not speak. Wrong firmware commands are out of scope.

## Side effects

Printers, NAS, Chromecast, and some Apple discovery can break. Reverse: Recovery **3 → 5**, then System Restore or re-enable discovery if you still need it.
