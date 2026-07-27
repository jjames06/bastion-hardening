# Browser policies and Encrypted Client Hello (ECH)

This page documents Bastion’s **browser privacy policies** and the optional **Encrypted Client Hello (ECH)** pack. It matches the behavior enforced in `Bastion-Hardening.ps1` (menu **6**, Recovery **3**, Dry Run, and Security audit).

---

## Scope

| Item | Behavior |
|------|----------|
| Supported browsers | **Firefox**, **Google Chrome**, **Brave** only |
| Who appears in the menu | **Installed** engines only (path detection). Missing browsers are never listed |
| Independent modes | Each installed browser can be Default, Medium, or Strict on its own |
| Section toggle | `BrowserPolicies` defaults **off** for bulk Apply; menu **6** still works when you open it |
| Quick Harden | Does **not** apply browser policies or ECH |

---

## Modes

| Mode | Effect |
|------|--------|
| **Default** | Best-effort **remove** Bastion-managed policies for that browser only (and any Bastion ECH pack for that browser). Backups are kept under the [data directory](DATA-DIRECTORY.md) when possible |
| **Medium** | Privacy baseline (telemetry / tracking / cookies style controls). Usually fewer site breakages than Strict |
| **Strict** | Medium **plus** HTTPS-Only style hardening. **Does not** enable Encrypted Client Hello (ECH) by itself |
| **ECH pack** | Optional **second** Yes/No **after** you choose Strict, for the **selected installed browser(s) only** |

### Encrypted Client Hello (ECH) is never automatic

Bastion will **not** turn on Encrypted Client Hello (ECH) because you:

- Installed or launched Bastion  
- Installed a browser  
- Chose Strict alone  
- Ran Dry Run or Security audit  
- Seeded `Bastion-Config.json` on first run  

ECH is applied **only** when you answer **Yes** to the separate Encrypted Client Hello (ECH) pack question under Strict for the browser(s) you selected. Fresh configs and defaults keep ECH **off** for every browser. Apply will not invent a Yes.

---

## What Encrypted Client Hello (ECH) is (plain language)

During a normal TLS handshake, the **Client Hello** can expose the destination hostname (SNI) to passive observers on the network path.

**Encrypted Client Hello (ECH)** is a TLS privacy feature: when client, server, and path support it, that material can be encrypted so passive observers learn less about which site you open.

Bastion’s “ECH pack” is a **best-effort policy lock** so the browser is encouraged or required to use ECH-related settings Bastion can set. It is **not** a guarantee that every site or network will complete handshakes with ECH, and it is **not** identical across browsers.

---

## What Bastion writes per browser (when you opt in)

### Firefox + Strict + ECH Yes

- Writes/updates Mozilla `distribution\policies.json` under the Firefox install tree  
- Locks Encrypted Client Hello (ECH) related preferences (for example `network.dns.echconfig.enabled` and related)  
- Bastion **never** sets `DisableEncryptedClientHello` (that would turn ECH **off**)  

### Chrome or Brave + Strict + ECH Yes

- Enterprise policy keys under the browser’s policy hive (HKLM policies)  
- Bastion sets an **intent marker** (`BastionEchLock`) and the strongest **transport** policies it can via enterprise policy (HTTPS-Only, DNS-over-HTTPS style settings as implemented in the script)  
- This is **not** the same preference model as Firefox’s `policies.json`  

### Strict without ECH (you answered No)

- HTTPS-Only / Medium-class privacy policies as designed for that mode  
- **No** Encrypted Client Hello (ECH) pack  

### Default (revert)

- Removes Bastion-managed policy material for **that browser only** (best-effort)  
- Clears Bastion’s saved ECH Yes for that browser  
- Does **not** claim to reverse unrelated third-party or MDM policies  

---

## Compatibility and honesty

| Risk | What you may see |
|------|------------------|
| HTTPS-Only (Strict) | Plain HTTP sites, mixed content, captive portals, and misconfigured HTTPS hosts may fail or warn |
| Encrypted Client Hello (ECH) | Some networks, middleboxes, or TLS interceptors mishandle ECH; sites may fail until you revert or use another browser |
| Cookie / tracking limits | Some SSO, banks, embeds, and older widgets need looser settings |

**Suggested pattern:** one installed browser on Strict (optional ECH) for daily private browsing; another on Medium or Default for awkward sites.

**Bulletproof rollback:** System Restore (main menu **13** / **R**).  
**Per-browser rollback:** menu **6** → that browser → **Default**.

---

## Dry Run, audit, and saved vs live

| Surface | What it reports |
|---------|-----------------|
| Dry Run (BrowserPolicies enabled) | For each **installed** browser: live mode and ECH on/off vs **wanted** intent from Bastion config |
| Dry Run (section off) | Notes how many supported browsers are installed; menu **6** still works independently |
| Security audit | Live/saved mode and Encrypted Client Hello (ECH) status per installed browser |
| Main menu summary | Compact wanted modes (e.g. `Firefox=Strict+ECH`) |

**Wanted** = what you saved in Bastion (menu / `Bastion-Config.json`).  
**Live** = what is detected on disk / registry right now.  
They can differ (for example after a manual edit, partial revert, or browser not restarted).

After policy changes, **fully quit** the browser (all windows) so policies reload.

| Browser | Check UI |
|---------|----------|
| Firefox | `about:policies` |
| Chrome | `chrome://policy` |
| Brave | `brave://policy` |

---

## Files involved

| Location | Role |
|----------|------|
| Bastion [data directory](DATA-DIRECTORY.md) | `Bastion-Config.json` (wanted modes + ECH flags), `Bastion-BrowserPolicies-State.json`, `Bastion-Session.json`, `browser-policy-backups/` |
| Firefox install tree | `distribution\policies.json` when Bastion manages Firefox |
| Chrome / Brave policy registry | Bastion-managed values when Bastion manages those browsers |

Deleting Bastion’s data directory does **not** by itself remove browser enterprise policies already written. Use menu **6** → **Default** per browser, or System Restore.

---

## Non-goals

- Bastion does not configure Edge, Opera, Vivaldi, or other engines in this version  
- Bastion does not claim ECH works on every network  
- Bastion does not enable ECH “to be thorough” without an explicit Yes  
- Bastion is not a full enterprise MDM replacement for browser fleets  

---

## Related documentation

- [Data directory](DATA-DIRECTORY.md)
- [README — Browser policies](../README.md#browser-policies)
- In-app **Help → page 7 (Browsers, Strict mode, and ECH)**
