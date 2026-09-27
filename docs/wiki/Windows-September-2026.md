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

1. Leave **KB5124008** installed. Install **KB5129195** (or later) so 25H2/24H2 reach UBR **9457**.
2. If ping by IP works and names fail, check whether DNS Client is Running. Do not start with `netsh winsock reset` on the only working session.
3. Recovery **9 → 3 Network** to restore prior DNS or DHCP.
4. Use one network path (wireless or wired).
5. Domain-joined PCs with Isolation **= 2**: follow Microsoft's set-to-0 steps. Home workgroup PCs can skip that.

Keep Files reinstall restored DNS Client on the computer used for this report. That is a last resort.

Full sentences, sources, and the version table: [operationlockedin.com/bastion/windows-september-2026](https://www.operationlockedin.com/bastion/windows-september-2026).

## Related

- [Known CVE checks](Cve-checks) (main menu **C**, Recovery **7**)
- [Recovery cookbook](Recovery-cookbook)
- [KNOWN-ISSUES.md](https://github.com/jjames06/bastion-hardening/blob/main/docs/KNOWN-ISSUES.md)
