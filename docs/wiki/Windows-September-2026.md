# September 2026 Windows update

This handbook page matches the product page [September 2026 Windows update](https://www.operationlockedin.com/bastion/windows-september-2026). English is the technical record. Bastion **v16.0** does not install Microsoft packages and does not change the DNS Client logon account.

## What this is

The 8 September 2026 Windows security update (**KB5124008**, Windows 11 25H2 build **26200.9445** / 24H2 **26100.9445**) is what broke name resolution and several VPN paths on a personal Windows 11 computer that also ran Bastion and a consumer VPN.

Microsoft has confirmed Always On VPN failures and domain-trust failures after that package. Microsoft has **not** listed DNS Client event **7023** (Access denied) as a known issue. That last symptom is a field observation, recorded so operators can recognise it.

## What Microsoft shipped

- **8 September 2026:** KB5124008. Public reporting described two Windows elevation-of-privilege flaws listed as exploited: CVE-2026-85880 (ALPC) and CVE-2026-81963 (Windows Update Stack).
- **14 September 2026:** out-of-band **KB5129195** (25H2 **26200.9457**, 24H2 **26100.9457**). Repairs Remote Desktop Services hangs, Plan9 folder shares for some Linux guests, and part of USB Audio Class 1.0. Also includes CVE-2026-62721 (User-Mode Power Service).

Bastion menu **C**, row **WIN-SEP2026**, treats **UBR 9457 / KB5129195** as the healthy floor for 25H2 and 24H2. Bastion starts a Windows Update scan and opens Settings. You finish Download and restart if Windows asks.

## What Microsoft has confirmed

- **Always On VPN** profiles that automatically fail over between IKEv2 and SSTP can stay in Connecting or report that the specified port is already in use. Workaround: pin one protocol.
- **Machine Identity Isolation** honoured at registry value **2** can break domain trust on domain controllers below Windows Server 2025 DFL. Workaround: set the value to **0**, restart, then `Test-ComputerSecureChannel -Repair`. A home workgroup PC without those keys is not on that path.
- RDS, Plan9/WSL shares, and part of USB Audio Class 1.0 are addressed by **KB5129195**.

## What showed up on a personal PC

Ping by numeric address still worked and names did not. `nslookup` to `127.0.0.1` had no listener on UDP 53. DNS Client logged **7023 Access denied**. DISM / Windows Update then failed with **0x800f0915**. Direct queries to a public resolver by IP still answered.

A connected consumer VPN that replaces system DNS can leave a dead local stub if the Windows DNS Client cannot start. Bastion optional DNS-over-HTTPS on physical adapters does not set the DNS Client ObjectName. VPN adapters are excluded from DNS Apply. A connected VPN overriding DNS is expected. See [SECURITY.md](https://github.com/jjames06/bastion-hardening/blob/main/SECURITY.md).

Using Ethernet and Wi-Fi at the same time is a separate local problem. Use one path.

## How to recover

Work these stages in order. The full sentences live on the [site page](https://www.operationlockedin.com/bastion/windows-september-2026). This is the path that restored a personal Windows 11 25H2 PC after names failed, a VPN stub sat on 127.0.0.1 with no UDP 53 listener, DNS Client logged **7023 Access denied**, and Microsoft Store, Windows Update, DISM (**0x800f0915**), and network troubleshooters all failed.

### 1. Recognise the pattern

- `ping 9.9.9.9` works, `ping google.com` fails: names are dead, the link is not.
- `nslookup google.com` showing Server **127.0.0.1** with no listener on UDP 53 is a dead local stub.
- `nslookup google.com 9.9.9.9` still answering means the public resolver works.

### 2. Do not start with stack resets

Skip `netsh winsock reset`, `netsh int ip reset`, and `Restart-Service Dnscache` as first moves. Do not uninstall **KB5124008**. Do not dual-home Ethernet and Wi-Fi.

### 3. One network path

Unplug Ethernet or turn Wi-Fi off. Disconnect the VPN only to test the physical path. Bastion Recovery **9 → 3** can restore prior DNS or DHCP. Hub **7** does not uninstall Microsoft updates.

### 4. DNS Client and adapter DNS

DNS Client should be Running / Automatic. Event **7023 Access denied** means it failed to start. Point the active adapter at a public resolver **by IP**. `ipconfig /flushdns` is safe. Empty IPv4 DNS plus leftover IPv6 `fec0` placeholders on ghost adapters send lookups the wrong way.

Changing the DNS Client logon account to LocalSystem was attempted under pressure. Keep Files is what put the service back to Running.

### 5. Store, Windows Update, DISM

Restore names first. Then take **KB5129195** (build **9457**). DISM **0x800f0915** means no source. `sfc /scannow` can still report no integrity violations. An ISO source can still fail. Store and `wsreset` need names.

### 6. Keep Files when Store and Update stay dead

Settings → System → Recovery → Reset this PC → **Keep my files**. Reinstall programs from official sources. Install **KB5129195** when Update offers it. Use one path.

### 7. Domain-joined only

Isolation registry **= 2**: set to **0**, restart, `Test-ComputerSecureChannel -Repair`. Always On VPN auto IKEv2/SSTP: pin one protocol.

## Related

- [Known CVE checks](Cve-checks) (main menu **C**, Recovery **7**)
- [Recovery cookbook](Recovery-cookbook)
- [KNOWN-ISSUES.md](https://github.com/jjames06/bastion-hardening/blob/main/docs/KNOWN-ISSUES.md)
