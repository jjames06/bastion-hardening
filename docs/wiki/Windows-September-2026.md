# September 2026 Windows update

English is the technical record for this handbook page. It is not a Microsoft support article. It does not claim that Bastion caused the outage. Bastion **v16.0** does not install Microsoft packages and does not change the DNS Client logon account.

Published 26 September 2026.

**If ping by IP works and names fail, start at [Fix names now](#fix-names-now).** Microsoft details, the field report, and Bastion versions are in [Background](#background).

## Fix names now

If ping by IP works and names fail, Microsoft Store, Windows Update, and DISM will fail too. Copy the commands in order. Do not start with `netsh winsock reset`. Do not skip to Keep Files until names are dead and DISM cannot reach a source.

### Commands to copy

Copy **one** command at a time. Paste it, read **Expected**, then go to the next. Where a command says `YOUR-ADAPTER`, replace that with the **Name** from group 2. Do not guess. Use one network path (Wi-Fi or Ethernet, not both). Disconnect the VPN only while you test the physical path. These commands do not assume which public DNS you use.

<details open>
<summary><strong>1. See if names are dead</strong> (Command Prompt)</summary>

#### 1. See if names are dead

Shell: **Command Prompt**. `9.9.9.9` is only a test address (Quad9). Any public IP that answers ping is enough to prove the link is up.

Command 1 of 4:

```text
ping -n 4 9.9.9.9
```

> **Expected:** Four replies with time in milliseconds. If this fails, the internet path is down. Stop here and fix the link (cable, Wi-Fi, modem) before DNS.

Command 2 of 4:

```text
ping -n 4 google.com
```

> **Expected:** If DNS works, four replies. If names are dead: could not find host, or a timeout, while `9.9.9.9` still replied.

Command 3 of 4:

```text
nslookup google.com
```

> **Expected:** Look at the **Server** line. If it is `127.0.0.1` or `::1`, a local stub (VPN, filter, or DoH proxy) is in the way. If it times out with no listener on UDP 53, that stub is dead.

Command 4 of 4:

```text
nslookup google.com 9.9.9.9
```

> **Expected:** An Address list for google.com. This asks Quad9 by IP as a **test only**. It proves a public resolver still works even when Windows default lookup does not. You may use `1.1.1.1` instead of `9.9.9.9` if you prefer Cloudflare as the test target.

</details>

<details>
<summary><strong>2. Write down the adapter Name, then check DNS Client</strong> (Windows PowerShell)</summary>

#### 2. Write down the adapter Name, then check DNS Client

Shell: **Windows PowerShell**. You need the **Name** from the first command for group 3. Typical names are `Wi-Fi` or `Ethernet`.

Command 1 of 3:

```powershell
Get-NetAdapter | Where-Object Status -eq 'Up' | Format-Table Name, Status, LinkSpeed
```

> **Expected:** One row you are using, Status **Up**. Copy the **Name** cell exactly, including spaces and capital letters. You will paste it into group 3 in place of `YOUR-ADAPTER`. If both Wi-Fi and Ethernet are Up, unplug one or turn one off, then run this again. Ignore VPN, Wintun, Bluetooth, and vEthernet rows.

Command 2 of 3:

```powershell
Get-Service Dnscache | Format-List Name, Status, StartType
```

> **Expected:** Status **Running**, StartType **Automatic**. If Status is Stopped, Event Viewer (Windows Logs, System) often shows event **7023 Access denied**. Do not run `Restart-Service Dnscache` as the first fix.

Command 3 of 3:

```powershell
Get-DnsClientServerAddress -AddressFamily IPv4 | Format-Table InterfaceAlias, ServerAddresses
```

> **Expected:** A public resolver or your router IP on a healthy path. Problem: `127.0.0.1`, `::1`, or blank on the adapter you wrote down. Disconnect the VPN and run this again if you still see `127.0.0.1`.

</details>

<details>
<summary><strong>3. Set a public resolver on YOUR adapter, then flush</strong> (Windows PowerShell, Run as administrator)</summary>

#### 3. Set a public resolver on YOUR adapter, then flush

Shell: **Windows PowerShell (Run as administrator)**. Replace `YOUR-ADAPTER` with the **Name** from group 2, keep the quotes. Copy **exactly one** of the four set commands, then flush, then nslookup. The field PC used Quad9. Cloudflare, Google, or automatic DHCP are equally valid. Do not run all four set commands.

Command 1 of 6 (optional, Quad9):

```powershell
Set-DnsClientServerAddress -InterfaceAlias "YOUR-ADAPTER" -ServerAddresses 9.9.9.9,149.112.112.112
```

> **Expected:** No error. Example: if group 2 showed Name `Wi-Fi`, this becomes `InterfaceAlias "Wi-Fi"`. If it says the alias was not found, the Name does not match. Run group 2 again.

Command 2 of 6 (optional, Cloudflare):

```powershell
Set-DnsClientServerAddress -InterfaceAlias "YOUR-ADAPTER" -ServerAddresses 1.1.1.1,1.0.0.1
```

> **Expected:** No error. Use this **instead of** Quad9, not in addition.

Command 3 of 6 (optional, Google Public DNS):

```powershell
Set-DnsClientServerAddress -InterfaceAlias "YOUR-ADAPTER" -ServerAddresses 8.8.8.8,8.8.4.4
```

> **Expected:** No error. Use this **instead of** Quad9 or Cloudflare, not in addition.

Command 4 of 6 (optional, automatic DHCP):

```powershell
Set-DnsClientServerAddress -InterfaceAlias "YOUR-ADAPTER" -ResetServerAddresses
```

> **Expected:** No error. Returns that adapter to automatic DNS from DHCP (usually your router). Use this if you do not want a public resolver.

Command 5 of 6 (always, after you chose one set command):

```text
ipconfig /flushdns
```

> **Expected:** Successfully flushed the DNS Resolver Cache.

Command 6 of 6 (always, after flush):

```text
nslookup google.com
```

> **Expected:** Server is no longer `127.0.0.1`. You should see addresses for google.com. Then retry `ping google.com`. If Server is still `127.0.0.1`, the VPN stub is still in the way. Disconnect the VPN.

</details>

<details>
<summary><strong>4. After names work: Windows image health</strong> (Command Prompt, Run as administrator)</summary>

#### 4. After names work: Windows image health

Shell: **Command Prompt (Run as administrator)**. Run these only after `ping google.com` works. If names are still dead, DISM cannot reach Microsoft.

Command 1 of 2:

```text
DISM /Online /Cleanup-Image /RestoreHealth
```

> **Expected:** The restore operation completed successfully. Failure `0x800f0915` means DISM could not reach a source. Restore names first. An ISO source can still fail.

Command 2 of 2:

```text
sfc /scannow
```

> **Expected:** Windows Resource Protection did not find any integrity violations, or it found files and repaired them. It can report no violations even when DISM failed with `0x800f0915`.

</details>

<details>
<summary><strong>5. Domain-joined computers only: Isolation value</strong> (Windows PowerShell, Run as administrator)</summary>

#### 5. Domain-joined computers only: Isolation value

Shell: **Windows PowerShell (Run as administrator)**. A home workgroup PC can skip this entire group.

Command 1 of 2:

```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name MachineIdentityIsolation -ErrorAction SilentlyContinue
```

> **Expected:** On a home PC, no output, or the property is missing. If MachineIdentityIsolation equals **2**, follow stage 7 below (set to 0, restart, repair the secure channel).

Command 2 of 2:

```powershell
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name MachineIdentityIsolation -ErrorAction SilentlyContinue
```

> **Expected:** Same as the previous command, for the policy key. No output, or not 2. If it is 2, treat it the same as the LSA value.

</details>

<details open>
<summary><strong>Do not run these first</strong></summary>

#### Do not run these first

These can drop the only working path while DNS Client is in Access denied.

```text
netsh winsock reset
```

> **Do not run first.** Rebuilds Winsock and can drop the only working path.

```text
netsh int ip reset
```

> **Do not run first.** Resets the TCP/IP stack and can drop the session.

```text
Restart-Service Dnscache
```

> **Do not run first.** When event 7023 Access denied is present, this restart fails.

### 1. Recognise the pattern

Confirm it is a name-resolution failure, not a dead internet link.

1. ping a public address by number (for example 9.9.9.9). If that replies, the path to the internet is up.
2. ping a name such as google.com. If that fails while the number works, Windows cannot resolve names.
3. Open Command Prompt and run `nslookup google.com` with no extra switches. If Server is 127.0.0.1 or ::1, a local stub (VPN, filter, or DoH proxy) is in the way. If there is no listener on UDP 53, that stub is dead.
4. `nslookup google.com 9.9.9.9` (or another public resolver by IP) still answering while the default lookup fails means the public resolver works and the local resolver does not.
5. Microsoft Store, Windows Update, and DISM RestoreHealth need names. They will look offline, spin, or return 0x800f0915 even though ping by IP works. Built-in network troubleshooters fail for the same reason.

### 2. Stop before the commands that drop the last path

Several common resets make a half-working session worse.

1. Do not start with `netsh winsock reset` or `netsh int ip reset`. Those rebuild the stack and can drop the only working path.
2. Do not `Restart-Service Dnscache` as a first move. On this failure the service often logs 7023 Access denied (Win32 5) and will not restart.
3. Do not ResetServerAddresses on an adapter that already has a working public resolver by IP.
4. Do not uninstall Knowledge Base 5124008 to chase DNS. That package closes elevation-of-privilege bugs Microsoft listed as exploited.
5. Do not leave Ethernet and Wi-Fi up together. Dual-home plus a VPN makes Network Connectivity Status Indicator report no internet and bounce routes.

### 3. Use one network path

Pick wireless or wired. Leave the other disconnected until names work.

1. Unplug Ethernet or turn Wi-Fi off. Do not leave both connected.
2. If a VPN is connected, disconnect it only long enough to test the physical path. While the tunnel is up, its DNS is expected to win. Privacy features such as cover traffic and extra hops reduce speed by design; they are not a broken radio.
3. If you use Bastion, Recovery hub 3 can restore prior DNS from the last Apply snapshot or return adapters to automatic DNS. Recovery hub 7 does not uninstall Microsoft updates.

### 4. Get names working on the physical adapter

Windows must have a running DNS Client and a reachable resolver that is not a dead 127.0.0.1 stub.

1. Open `services.msc`. Find DNS Client (Dnscache). It should be Running, start type Automatic. Event Viewer, Windows Logs, System, event 7023 with Access denied means the service failed to start.
2. On the computer in this report the service had been NetworkService and then failed. Changing the logon account to LocalSystem was attempted under pressure. That is not the first recommendation. Keep Files reinstall is what put the service back to Running and Automatic.
3. Set IPv4 DNS on the active adapter to a public resolver by IP, or return it to automatic DHCP. Quad9, Cloudflare, and Google are all valid. Empty IPv4 DNS plus leftover IPv6 site-local fec0 placeholders on ghost adapters will send lookups the wrong way.
4. `ipconfig /flushdns` is safe. Confirm `nslookup google.com` no longer uses 127.0.0.1, then retry `ping google.com`.
5. Leave VPN custom DNS for when the tunnel is connected. Test the physical path with the VPN disconnected.

### 5. Microsoft Store, Windows Update, and DISM

These features cannot repair themselves while names are dead.

1. Restore name resolution first. Then open Settings, Windows Update, and take Knowledge Base 5129195 (25H2 and 24H2 build 9457) or later.
2. If `DISM /Online /Cleanup-Image /RestoreHealth` returns 0x800f0915, it could not reach a source. `sfc /scannow` may still report no integrity violations. That combination means the component store cannot talk to Microsoft, not that every file is fine.
3. Mounting a matching Windows 11 ISO and pointing DISM at it can still fail when the servicing stack and name path are both damaged. Treat ISO repair as optional, not a guarantee.
4. Microsoft Store and `wsreset.exe` need names and Windows Update. They will not recover until DNS works, or until Keep Files reinstall replaces the Store components.

### 6. Keep Files reinstall when Store and Update stay dead

When DNS Client will not stay healthy, DISM cannot reach a source, and Store plus Windows Update remain broken, Keep Files is the recovery that restored this computer.

1. Use Settings, System, Recovery, Reset this PC, Keep my files. That reinstalls Windows, keeps personal files, and removes most installed programs.
2. After the reinstall, DNS Client should be Running and Automatic again. The build may still be 26200.9445 (Knowledge Base 5124008) until Windows Update can offer 5129195.
3. Reinstall programs from official sources. Reinstall the VPN if you use one. Re-download Bastion from [GitHub Latest](https://github.com/jjames06/bastion-hardening/releases/latest) if you still want it.
4. Use one network path. Install Knowledge Base 5129195 when Windows Update offers it. System Restore from before the cumulative update is the other full rollback if you created a point and still have it.

### 7. Domain-joined computers only

A home workgroup PC without these registry values can skip this stage.

1. If `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MachineIdentityIsolation` or the DeviceGuard policy value is 2, Microsoft's documented workaround is to set it to 0, restart, then `Test-ComputerSecureChannel -Repair`.
2. Always On VPN that automatically fails over between IKEv2 and SSTP should be pinned to one protocol until Microsoft ships a permanent fix.

</details>

<details>
<summary><strong>Background</strong> (what Microsoft shipped, the field report, Bastion versions)</summary>

## Background

Read this after names work, or if you need to know what Microsoft confirmed and what Bastion does. It is not required to run the commands above.

### What this page is

The 8 September 2026 Windows security update is what broke name resolution and several VPN paths on the personal Windows 11 computer used to maintain Bastion. Bastion did not write the DNS Client service account, did not stop the DNS Client service, and did not install that Microsoft package.

A consumer VPN that takes over DNS while connected, together with Bastion's optional encrypted DNS on physical adapters and a strict inbound firewall, is a demanding environment for that update. That combination did not write the regression. It is the combination that fails first when Windows networking misfires.

Microsoft has confirmed Always On VPN failures and domain-trust failures after the 8 September cumulative update. Microsoft has not listed DNS Client event 7023 (Access denied) as a known issue. That symptom is recorded here so other people who run Bastion can recognise it.

### What Microsoft shipped

On 8 September 2026 Microsoft released Knowledge Base article 5124008 for Windows 11 versions 24H2 and 25H2. That package moves 25H2 to OS build 26200.9445 and 24H2 to 26100.9445. Public reporting described a record set of Common Vulnerabilities and Exposures identifiers, including two Windows elevation-of-privilege flaws that Microsoft listed as exploited in the wild: CVE-2026-85880 in Advanced Local Procedure Call, and CVE-2026-81963 in the Windows Update Stack.

On 14 September 2026 Microsoft released an out-of-band cumulative update, Knowledge Base article 5129195, which moves 25H2 to 26200.9457 and 24H2 to 26100.9457. That package repairs Remote Desktop Services instability from the 8 September update, restores Plan9 folder shares for some Linux virtual machines, partly repairs USB Audio Class 1.0 in multichannel modes, and includes protection for CVE-2026-62721 in Windows User-Mode Power Service. Windows 11 version 26H1 received Knowledge Base article 5129194. Windows 10 version 22H2 received Knowledge Base article 5129236.

Bastion version 16.0 already treats those out-of-band floors as the healthy line in the known CVE catalogue (main menu **C**, row **WIN-SEP2026**). A 25H2 computer still on 26200.9445 is reported Exposed until Knowledge Base 5129195 is installed, or the update build revision is 9457 or higher. Bastion starts a Windows Update scan and opens Settings. It does not silently install the package.

### What Microsoft has confirmed

### Always On VPN

After Knowledge Base 5124008 (25H2 and 24H2) or 5124012 (26H1), Always On VPN profiles that automatically fail over between IKEv2 and SSTP can stay in Connecting, retry without succeeding, or report that the specified port is already in use. Microsoft's temporary workaround is to pin the profile to a single protocol. That is an enterprise Always On VPN issue. A consumer VPN client is a different product. The same cumulative update is the package that changed the Windows networking stack.

### Machine Identity Isolation and domain trust

On domain-joined computers, Knowledge Base 5124008 began honouring Machine Identity Isolation when the registry value is 2 (enforcement). That feature is only supported with Windows Server 2025 domain functional level. Workstations against older domain controllers can lose their secure channel. Microsoft's workaround is to set the value to 0, restart, then repair the secure channel. A home computer that is not domain-joined, and that does not have those registry values, is not on that path.

### Remote Desktop, USB audio, and Plan9 shares

Remote Desktop Services could hang after the 8 September update. That class of failure is resolved by Knowledge Base 5129195. USB Audio Class 1.0 devices could fail to start. Eight-channel and 3D modes are partly fixed in the same out-of-band package. Host folder shares into some Hyper-V Linux guests using Plan9, including some Windows Subsystem for Linux setups, failed until 5129195.

### File History

Some computers could not create or update File History backups after Knowledge Base 5124008, including a false Reconnect your drive message. Microsoft listed a later September package (Knowledge Base 5124010 and updates on or after 22 September 2026) as the repair for that class of failure.

### What showed up on a personal computer

This report is from one Windows 11 Pro 25H2 computer used to maintain Bastion. It had Bastion applied, a consumer VPN connected at times, and both a wired adapter and a wireless adapter. It is not a client site, an office domain, or a named internet provider.

After Knowledge Base 5124008 installed, ping by numeric address still worked and names did not. nslookup aimed at 127.0.0.1 had no listener on UDP port 53. The DNS Client service (Dnscache) logged event 7023 with Access denied (Win32 exit code 5). Windows Update and DISM RestoreHealth then failed with 0x800f0915 because the computer could not reach Microsoft's source over a broken name path.

Direct queries to a public resolver by IP still answered. That pattern is a dead local stub and a dead DNS Client, not a dead internet link. Changing the DNS Client logon account, resetting adapter DNS, and similar live repairs were attempted under pressure. Several of those commands can drop the only working path. The recovery that restored Windows features on this computer was Keep Files reinstall, then putting programs back. That is a last resort, not the first step.

After that reinstall the DNS Client was Running and Automatic again. The computer was still on build 26200.9445 (Knowledge Base 5124008) until Windows Update could offer Knowledge Base 5129195. Machine Identity Isolation keys on this computer were absent, so the domain-trust known issue was not the path that hit it.

A separate local problem, not caused by the cumulative update, was using Ethernet and Wi-Fi at the same time. Windows then reported no internet and bounced routes, and the wireless radio stayed on a slow 2.4 GHz channel. Use one path at a time: wireless or wired, not both.

### What current Bastion versions change

The published product version is 16.0. Unpublished 15.9.9 work was folded into 16.0. Always start with `Bastion-Hardening.bat` from the official zip.

| Version | Status | What it is |
|---------|--------|------------|
| **16.0** | Current | Known CVE checks (main menu **C**, Recovery hub **7**). WIN-SEP2026 floor for 25H2 and 24H2 is update build revision 9457 (Knowledge Base 5129195). Defender update health. Modular source with MANIFEST integrity. GNU GPLv3. |
| **15.9.8** | Superseded | Optional LAN hygiene on the Windows computer only. Recovery home-gateway fingerprint after you confirm. No assumed modem brand. Prefer 16.0. |
| **15.9.7 through 15.9.0** | Superseded | Modular layout, launch fixes, dark console, and Help colours. 15.9.1 was retracted. Prefer 16.0. |
| **15.8.x and earlier 15.x** | Best-effort | Monolith era through 15.8.4. Prefer 16.0 for CVE checks and Defender update health. |

### What Bastion does

- Optional DNS Apply writes the IPv4 resolver addresses you chose (Quad9 by default, or Cloudflare, Google, or OpenDNS) on eligible physical adapters, and it registers Windows DNS-over-HTTPS the same way Settings, Edit DNS does. VPN, WSL, Docker, loopback, and similar virtual adapters are excluded from that list.
- A connected VPN is expected to override those adapter DNS settings while the tunnel is up. That is documented in Bastion's security policy as expected behaviour, not a Bastion defect. See [SECURITY.md](https://github.com/jjames06/bastion-hardening/blob/main/SECURITY.md).
- Firewall Apply sets inbound Block and outbound Allow, and it disables inbound groups such as File and Printer Sharing, Network Discovery, Remote Desktop, and Windows Remote Management. It does not add outbound blocks for DNS.
- High-risk services Bastion can disable include Print Spooler, Server (SMB sharing), UPnP, and related items. The DNS Client (Dnscache) is not in that list. Bastion does not rewrite the DNS Client ObjectName, does not set Machine Identity Isolation, and does not install Knowledge Base 5124008.
- Recovery hub 3 can reset DNS to automatic or restore the encrypted prior-DNS snapshot from the last Apply. Recovery hub 7 reverses CVE-catalogue registry writes Bastion recorded. Neither hub uninstalls a Microsoft cumulative update. System Restore (main menu **13** or **R**) remains the strongest full rollback.

### What caused it

The 8 September 2026 cumulative update (Knowledge Base 5124008 on 25H2 and 24H2) is the package that moved the computer in this report to 26200.9445. Microsoft has already confirmed that it broke Always On VPN automatic protocol failover and, where Isolation was set to enforcement, domain trust. Independent reports describe a networking-stack regression rather than a bad Intune profile.

A consumer VPN that replaces system DNS while connected can point lookups at a local stub on 127.0.0.1, flush the resolver cache, and leave no listener on UDP 53 if the Windows DNS Client cannot start. When names fail and numeric ping still works, that is the signature.

DNS Client event 7023 Access denied means the service failed to start. On the computer in this report it had been running as NetworkService. That is a Windows service permission failure after the cumulative update, not a Bastion Apply line. The Bastion DNS, services, and Apply modules do not set the DNS Client logon account.

Bastion's optional DNS-over-HTTPS on physical adapters, inbound firewall posture, and a computer that had wired, wireless, and VPN paths up at once made Windows Network Connectivity Status Indicator and VPN reconnect logic less forgiving. Those settings did not create Knowledge Base 5124008.

Keep Files reinstall of Windows put DNS Client back to Running and Automatic on this computer. After that, install Knowledge Base 5129195 when Windows Update offers it, and use one network path. VPN privacy features that add cover traffic or extra hops reduce speed by design. That is separate from a wireless radio parked on 2.4 GHz.

</details>

## Sources

- [Microsoft Learn: Windows 11 version 25H2 known issues (Knowledge Base 5124008)](https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-25h2)
- [Microsoft Support: Knowledge Base 5124008](https://support.microsoft.com/help/5124008)
- [Microsoft Support: Knowledge Base 5129195 out-of-band](https://support.microsoft.com/help/5129195)
- [BleepingComputer: Microsoft September 2026 updates break Always On VPN](https://www.bleepingcomputer.com/news/microsoft/microsoft-september-2026-windows-updates-break-always-on-vpn-connections/)
- [BleepingComputer: Knowledge Base 5124008 domain trust / Machine Identity Isolation](https://www.bleepingcomputer.com/news/microsoft/windows-11-kb5124008-update-breaks-domain-trust-for-some-users/)
- [Microsoft Q&A: Always On VPN fails after Knowledge Base 5124008](https://learn.microsoft.com/en-us/answers/questions/5998351/always-on-vpn-fails-after-installing-kb5124008-on)
- [The Hacker News: September 2026 Patch Tuesday including CVE-2026-85880 and CVE-2026-81963](https://thehackernews.com/2026/09/microsoft-patches-record-974-flaws.html)
- [Known CVE checks](Cve-checks) (WIN-SEP2026 floor is Knowledge Base 5129195 on 25H2)
- [SECURITY.md](https://github.com/jjames06/bastion-hardening/blob/main/SECURITY.md) (VPN override of DNS is expected)

## Related

- [Known CVE checks](Cve-checks) (main menu **C**, Recovery **7**)
- [Recovery cookbook](Recovery-cookbook)
- [KNOWN-ISSUES.md](https://github.com/jjames06/bastion-hardening/blob/main/docs/KNOWN-ISSUES.md)


