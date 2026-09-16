# Threat Hunt Report — Devices Accidentally Exposed to the Internet

**Analyst:** Tye (Tyler) Kleffer
**Hunt Platform:** Microsoft Defender for Endpoint (MDE), Advanced Hunting (KQL)
**Hunt Type:** Hypothesis-driven exposure/brute-force hunt
**Scenario Source:** LogNPacific Cyber Range — "entropy-gorilla"
**Outcome:** Confirmed negative — exposure and attack attempts real; no breach

---

## 1. Preparation

**Goal:** Set up the hunt by defining what we're looking for.

During routine maintenance, the security team was tasked with checking
whether any VMs in the shared services cluster (DNS, Domain Services, DHCP,
etc.) had been mistakenly exposed to the public internet, and whether any
brute-force login attempts — successful or not — had occurred against them
from external sources.

**Hypothesis:** If any of these devices were unknowingly exposed, and some
of the older machines lack account-lockout policies for excessive failed
login attempts, it's possible an external actor could have successfully
brute-forced their way in during the exposure window.

**Scope:** `windows-target-1` (referred to by MDE as `windows-target-` due
to name truncation), used here as the observed honeypot device.

---

## 2. Data Collection

**Goal:** Gather relevant data from logs, network traffic, and endpoints.

Confirmed recent telemetry existed across the tables needed to test the
hypothesis:

- `DeviceInfo`
- `DeviceLogonEvents`
- `DeviceNetworkEvents` (used to independently confirm the exposure itself)

---

## 3. Data Analysis

**Goal:** Analyze the data to test the hypothesis.

### Step 1 — Confirm the device was actually internet-facing

```kql
DeviceNetworkEvents
| where ActionType == "InboundConnectionAccepted"
| where not(ipv4_is_private(RemoteIP))
| project Timestamp, DeviceName, LocalIP, LocalPort, RemoteIP, RemotePort, Protocol, InitiatingProcessFileName
| order by Timestamp desc
```

**Finding:** `windows-target-` had accepted inbound connections from
non-private (public internet) IP addresses over **several days**, confirming
the exposure was real and not a brief or theoretical window. A sample of the
accepted connections:

| Time | Device | Local IP:Port | Remote IP | Protocol |
|---|---|---|---|---|
| Apr 1, 2026 8:41:56 | windows-target- | 10.0.0.155:3389 | 191.101.51.162 | TCP |
| Apr 1, 2026 7:59:54 | windows-target- | 10.0.0.155:3389 | 194.163.159.77 | TCP |
| Apr 1, 2026 7:32:44 | windows-target- | 10.0.0.155:3389 | 194.180.176.29 | TCP |
| Apr 1, 2026 7:30:04 | windows-target- | 10.0.0.155:3389 | 160.250.181.37 | TCP |
| Apr 1, 2026 7:28:20 | windows-target- | 10.0.0.155:135 | 64.227.90.185 | TCP |
| Apr 1, 2026 7:25:13 | windows-target- | 10.0.0.155:139 | 147.185.133.78 | TCP |
| Apr 1, 2026 7:05:01 | windows-target- | 10.0.0.155:3389 | 45.88.138.39 | TCP |
| Apr 1, 2026 7:03:26 | windows-target- | 10.0.0.155:3389 | 27.124.46.30 | TCP |
| Apr 1, 2026 7:00:45 | windows-target- | 10.0.0.155:3389 | 98.81.85.17 | TCP |
| Apr 1, 2026 6:42:34 | windows-target- | 10.0.0.155:139 | 205.210.31.21 | TCP |
| Apr 1, 2026 6:36:32 | windows-target- | 10.0.0.155:3389 | 94.72.110.157 | TCP |

The traffic was overwhelmingly against **port 3389 (RDP)**, with a handful
of hits against **135 (RPC)** and **139 (NetBIOS)** — a distinctly
"internet background radiation" pattern of opportunistic scanners and bots
hitting classic Windows remote-access ports, exactly as the scenario
predicted for a machine left exposed for an extended window.

### Step 2 — Check for failed logon volume by source

```kql
// Check most failed logons
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```

**Finding:** Multiple distinct external IP addresses had generated repeated
failed logon attempts against the device — consistent with active
brute-force attempts, not a one-off misfire.

### Step 3 — Check whether any of those IPs ever succeeded

```kql
let RemoteIPsInQuestion = dynamic(["119.42.115.235","183.81.169.238",
"74.39.190.50", "121.30.214.172", "83.222.191.62", "45.41.204.12",
"192.109.240.116"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```

And more generally, checking the device as a whole for any successful logon
at all during the exposure window:

```kql
DeviceLogonEvents
| where DeviceName has "windows-target"
| where ActionType == "LogonSuccess"
| summarize SuccessCount = count() by RemoteIP, AccountName
```

**Finding: no results.** None of the top failed-attempt source IPs ever
recorded a successful logon, and a broader sweep of the device for *any*
successful logon during the relevant window also returned nothing.

### Step 4 — Explicit brute-force-success join (belt and suspenders)

To be thorough, failed and successful logons were explicitly joined on
`RemoteIP` to catch any pattern the simpler checks might have missed (e.g.
a source IP with failures against one account but a success against a
*different* account):

```kql
let FailedLogons = DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize FailedLogonAttempts = count() by ActionType, RemoteIP, DeviceName
| order by FailedLogonAttempts;
let SuccessfulLogons = DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where isnotempty(RemoteIP)
| summarize SuccessfulLogons = count() by ActionType, RemoteIP, DeviceName, AccountName
| order by SuccessfulLogons;
FailedLogons
| join SuccessfulLogons on RemoteIP
| project RemoteIP, DeviceName, FailedLogonAttempts, SuccessfulLogons, AccountName
```

**Finding:** No matching rows — no remote IP anywhere in the dataset showed
both failed *and* successful logon activity against this device.

---

## 4. Investigation

**Goal:** Investigate the suspicious findings and map them to known TTPs.

The device was genuinely, materially exposed to the public internet for
several days, and drew real, sustained attacker attention as a result —
numerous distinct external sources probing RDP, RPC, and NetBIOS, and
multiple brute-force attempts against its logon surface. Despite that
sustained pressure, **every available data source agrees: no successful
external logon ever occurred.** This is a clean negative finding, not an
absence-of-looking — three independent queries (direct success-count sweep,
targeted check of the top offending IPs, and an explicit failed/success
join) all converged on the same answer.

### MITRE ATT&CK Mapping

| Observation | Tactic | Technique | Explanation |
|---|---|---|---|
| VM was internet-facing | Initial Access | **T1133** — External Remote Services | Exposed RDP/RPC/NetBIOS services could be reached directly from the public internet |
| Public inbound connections accepted | Initial Access / Recon | **T1210** — Exploitation of Remote Services | Multiple external actors attempted to connect to exposed services |
| Repeated failed logon attempts | Credential Access | **T1110** — Brute Force | Many login attempts across multiple source IPs consistent with credential-guessing |
| No successful logons | Credential Access | **T1078** — Valid Accounts *(negative)* | Attackers' brute-force attempts failed; no valid credentials were obtained |

**Assessment:** Real, sustained exposure and real attacker interest — but no
compromise. The device's account-lockout/authentication controls held under
active, multi-source brute-force pressure for the duration of the exposure
window observed.

---

## 5. Response

**Goal:** Mitigate any confirmed threats.

Since no breach was confirmed, response focused on closing the exposure and
hardening against a repeat, rather than incident containment:

- **Immediate remediation:** the device's exposed ports (3389/RDP in
  particular) should be pulled behind a VPN or bastion/jump-host rather than
  directly reachable from the internet.
- **No account compromise to remediate** — no credential rotation was
  required for this device based on the evidence gathered, since no
  successful unauthorized logon occurred.
- **Recommended hardening regardless of the clean outcome:** enable account
  lockout policies on any legacy device that currently lacks them, so a
  future exposure window doesn't rely entirely on attacker inability to
  guess a password.

---

## 6. Documentation

**Goal:** Record findings for future reference.

This report constitutes that documentation. In short: `windows-target-` was
confirmed exposed to the public internet for several days via ports 3389,
135, and 139, and drew sustained brute-force attempts from at least seven
distinct external IP addresses. Three independent logon-event queries all
confirmed **no successful external logon occurred** at any point during the
observed window — the exposure was real, the attacker interest was real, but
the compromise did not happen.

---

## 7. Improvement

**Goal:** Improve the security posture and refine the hunting process.

- **Prevent exposure at the source, not just detect it after the fact.**
  This device should never have had RDP/RPC/NetBIOS reachable from the
  public internet in the first place — a periodic automated sweep for
  publicly-reachable management ports on the shared-services cluster would
  catch this class of misconfiguration before it becomes a live target.
- **Account lockout should be a baseline requirement**, not an
  exception-by-age. The scenario explicitly notes some older devices lack
  lockout policy — that's a standing risk regardless of whether this
  particular brute-force attempt happened to fail.
- **Don't stop at "no successful logon found."** The extra step of
  explicitly joining failed and successful logons by IP (Step 4) closed a
  gap the simpler queries could have missed — a source IP succeeding under a
  *different* account than the one it was failing against. That join is
  worth keeping as a standard step in any brute-force hunt, not just when
  results look suspicious.
- **Process improvement:** validating the exposure claim independently via
  `DeviceNetworkEvents` (rather than assuming it from the scenario brief
  alone) turned "several days" from an assumption into a confirmed,
  evidenced timeframe — worth doing first in any hunt built around a
  reported misconfiguration, since the actual exposure window shapes how far
  back the rest of the investigation needs to look.

---

## Appendix: Indicators of Compromise (Attacker Activity, Unsuccessful)

| Type | Indicator |
|---|---|
| Exposed device | `windows-target-` (truncated from `windows-target-1`), internal IP `10.0.0.155` |
| Exposed ports | 3389 (RDP), 135 (RPC), 139 (NetBIOS) |
| Attacking IPs (sample) | 191.101.51.162, 194.163.159.77, 194.180.176.29, 160.250.181.37, 64.227.90.185, 147.185.133.78, 45.88.138.39, 27.124.46.30, 98.81.85.17, 205.210.31.21, 94.72.110.157 |
| Top brute-force source IPs checked | 119.42.115.235, 183.81.169.238, 74.39.190.50, 121.30.214.172, 83.222.191.62, 45.41.204.12, 192.109.240.116 |
| Successful unauthorized logons | **None confirmed** |

## Appendix: MITRE ATT&CK Coverage

`T1133` External Remote Services · `T1210` Exploitation of Remote Services · `T1110` Brute Force · `T1078` Valid Accounts *(negative — no valid credentials obtained)*

---

*Hunt conducted against the LogNPacific "entropy-gorilla" cyber range
scenario, using Microsoft Defender for Endpoint Advanced Hunting.*
