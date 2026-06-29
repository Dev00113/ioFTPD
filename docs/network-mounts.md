---
title: Network Mount Manager
---

# Network Mount Manager

> **Available from:** v8.1.0

ioFTPD can automatically establish, monitor, and reconnect UNC network shares
(`\\server\share\...`) referenced in `.vfs` files — without any manual intervention
or daemon restart.

---

## Overview

When ioFTPD loads a `.vfs` file it registers every UNC share root it finds in a
health table. Each registered share gets its own background timer that periodically
probes the share and reconnects if necessary.

Three layers of protection work together:

| Layer | Mechanism | Latency |
|---|---|---|
| **Proactive** | Background timer probes every share on a configurable interval | Up to `Network_Check_Interval` (default 60 s) |
| **Reactive** | `IoCreateFile` retries inline on `ERROR_NETNAME_DELETED` (dropped connection) | Milliseconds — transparent to the FTP client |
| **Event-driven** | `NotifyAddrChange` watch thread wakes all down-share timers the moment any NIC state changes | Seconds after link recovery |

The credential file (`etc\netmounts.cfg`) is **entirely optional**. Health monitoring
and reconnect work for any UNC share regardless — the credential file is only needed
for shares that require a username and password different from the account ioFTPD runs
as.

---

## Session 0 and Drive Letters

ioFTPD runs as a Windows service in **Session 0** (the service session). Drive letters
mapped by an interactive user (e.g. `Z:\` mapped on the administrator desktop) are
**not visible** in Session 0 — they exist only in the interactive user's session.

**Use UNC paths directly in `.vfs` files for network shares:**

```
# Works reliably in Session 0:
"\\nas.local\media\movies"  /movies

# Unreliable — Z: may not exist in Session 0:
Z:\movies  /movies
```

Local fixed drives (`C:\`, `D:\`, etc.) and drives mounted via Windows NFS Client
Services are session-independent and always work.

---

## Quick Start

**No credentials needed (domain share or open share):**

1. Use UNC paths in your `.vfs` file — health monitoring is automatic.
2. ioFTPD will log `Network mount connected: \\server\share` at startup once the first
   probe succeeds.

**Shares requiring a username and password:**

1. Add `Network_Mounts_File = etc\netmounts.cfg` to the `[Ftp]` section of
   `ioFTPD.ini`.
2. Create `etc\netmounts.cfg` with one line per share:

```
\\nas.local\media    ftpuser    "my secret"
```

3. Restart ioFTPD (or `SITE REHASH` to pick up credential changes without a
   full restart — see [Rehash](#rehash)).

---

## `netmounts.cfg` Format

Each non-comment line defines credentials for one share root:

```
<\\server\share>  [username]  [password]  [domain]
```

- The UNC share root (`\\server\share`) is required; all other fields are optional.
- Fields containing spaces **must** be surrounded by double quotes.
- `""` (empty quotes) passes an explicit blank password — needed for guest accounts
  on older Samba/SMBv1 configurations.
- Lines beginning with `#` are comments.
- Forward slashes are accepted: `//server/share` is treated the same as
  `\\server\share`.
- Trailing slashes are stripped automatically.
- Matching against `.vfs` paths is **case-insensitive**.

### Examples

```ini
# NAS requiring username and password
\\nas.local\media            ftpuser         "my s3cr3t"

# Share name or password containing spaces
"\\file server\share name"   "domain user"   "pass word"    CORP

# Workgroup NAS with explicit domain
\\backup-server\archive      svcacct         P@ssw0rd       WORKGROUP

# Guest access with blank password (older SMB / Samba configurations)
\\oldnas\public              guest           ""

# Domain-accessible share — monitoring only, no credentials needed
# (leave this line commented out or omit entirely; Windows handles auth)
# \\fileserver\data
```

### Path Matching Rules

This section covers mistakes that are easy to make and produce no error — ioFTPD silently
falls back to the service account if a credential entry is not found.

#### Capitalisation — safe, last entry wins

Matching is case-insensitive, so `\\NAS01\Media` and `\\nas01\media` are treated as the
same share. If you write the same share twice with different capitalisation, **the second
entry silently overwrites the first** — no warning is logged.

```ini
# Both lines refer to the same share — only the second credentials will be used
\\NAS01\media    ftpuser    password1
\\nas01\media    ftpuser    password2   # this one wins, silently
```

**Rule:** Pick one capitalisation and use it consistently in both `netmounts.cfg` and
your `.vfs` file.

---

#### IP address vs hostname — two completely different entries

`\\192.168.1.10\media` and `\\nas01\media` may point to the same physical server, but
ioFTPD treats them as completely separate shares. **No DNS lookup is ever performed.**
Each form gets its own health timer and its own credential lookup.

The consequence: if your `.vfs` file uses the hostname but `netmounts.cfg` has the IP
address, **credentials are silently never applied**. ioFTPD finds no matching entry and
falls back to the Windows service account with no error or warning.

```ini
# In your .vfs file:
"\\nas01\media"   /media

# WRONG — IP in netmounts.cfg, hostname in .vfs — they will never match:
\\192.168.1.10\media    ftpuser    password

# CORRECT — same form as the .vfs entry:
\\nas01\media            ftpuser    password
```

**Rule:** Use the exact same form — either always the IP or always the hostname — in
both files.

---

#### Short hostname vs fully-qualified domain name (FQDN)

`\\nas01\media` and `\\nas01.domain.com\media` are treated as different shares for the
same reason. A credential entry for the short name will never match a `.vfs` path written
as the FQDN, and vice versa.

```ini
# In your .vfs file:
"\\nas01.domain.com\media"   /media

# WRONG — short name in netmounts.cfg, FQDN in .vfs:
\\nas01\media               ftpuser    password

# CORRECT — FQDN in both places:
\\nas01.domain.com\media    ftpuser    password
```

**Rule:** Match the form exactly. If your `.vfs` file uses the FQDN, `netmounts.cfg`
must use the FQDN too.

---

#### Quick reference

| Situation | Result | Safe? |
|---|---|---|
| Same path, different capitalisation | Treated as one share; last entry's credentials win | ✓ Works — but confusing |
| IP address in one file, hostname in the other | Treated as two separate shares; credentials never apply | ✗ Silent failure |
| Short hostname in one file, FQDN in the other | Treated as two separate shares; credentials never apply | ✗ Silent failure |

**Tip:** Copy the UNC path directly from your `.vfs` file and paste it into
`netmounts.cfg`. Retyping it is the most common source of these mismatches.

---

### Security

Passwords are stored in cleartext. Restrict file access:

- `SYSTEM`: Full Control
- `Administrators`: Full Control
- All other accounts: No Access

ioFTPD zeros credential memory with `SecureZeroMemory` at shutdown and never writes
passwords to any log file.

---

## `ioFTPD.ini` Configuration

All keys go in the `[Ftp]` section:

```ini
[Ftp]

; Path to the optional credential file (relative to ioFTPD.exe directory or absolute).
; Health monitoring is active for all UNC shares regardless of whether this key is set.
Network_Mounts_File        = etc\netmounts.cfg

; Seconds between health probes when a share is reachable (default: 60, minimum: 5).
Network_Check_Interval     = 60

; Maximum seconds between reconnect attempts when a share is offline (default: 300, minimum: 10).
Network_Max_Retry_Interval = 300
```

---

## How Health Monitoring Works

### One timer per share root

The health table is keyed on the **share root** (`\\server\share`), not the full path.
All `.vfs` entries under the same share use one health record and one timer:

```
.vfs entries                              Health table
\\nas1\drive1\movies    /movies  ─┐
\\nas1\drive1\uploads   /up      ─┼─→  \\nas1\drive1  [1 timer, 1 health record]
\\nas1\drive1\archive   /arch    ─┘

\\nas2\data\files       /files   ──→  \\nas2\data    [1 timer, 1 health record]
```

### Probe and backoff schedule

When a share is **healthy**: timer fires every `Network_Check_Interval` (default 60 s).

When a share goes **offline**: exponential backoff — 10 s → 20 s → 40 s → 80 s →
160 s → capped at `Network_Max_Retry_Interval` (default 300 s).

When a share **recovers**: timer resets to `Network_Check_Interval` immediately.

### Startup stagger

Initial probes are spread 2.5 s apart across shares to avoid a burst of simultaneous
network calls at service start. With 10 shares all probes complete within 25 s of
startup.

### Network change detection

A dedicated watch thread calls `NotifyAddrChange` (overlapped) and wakes all
offline-share timers the moment any network interface changes state — NIC reconnected,
DHCP renewed, VPN connected. This means ioFTPD typically reconnects within seconds of
a network recovery, rather than waiting for the next timer tick.

If `NotifyAddrChange` registration fails at startup (e.g. network stack not yet ready),
the thread retries automatically every 30 s.

---

## SMB Compatibility

`WNetAddConnection2A` and the Windows SMB redirector handle all protocol negotiation —
ioFTPD is not involved in which SMB version is used. Windows automatically negotiates
the highest mutually supported version.

| System | Protocol | Support |
|---|---|---|
| Windows Server / workstation shares | SMBv2/3 | ✓ Full |
| Linux Samba 4.x (Ubuntu, Debian, RHEL, Alpine…) | SMBv2/3 | ✓ Full |
| Synology NAS | Samba 4.x (SMBv3) | ✓ Full |
| QNAP NAS | Samba 4.x (SMBv3) | ✓ Full |
| TrueNAS / FreeNAS | Samba 4.x (SMBv3) | ✓ Full |
| UnRAID | Samba 4.x (SMBv3) | ✓ Full |
| NetApp ONTAP, EMC Isilon/PowerScale | SMBv3 | ✓ Full |
| Azure Files, AWS FSx, Google Cloud Filestore | SMBv3 | ✓ Full |
| macOS (Windows Sharing enabled) | Samba (SMBv2/3) | ✓ Full |
| Windows NFS Client Services | Appears as local drive | ✓ via drive letter |
| Older Samba requiring SMBv1 only | SMBv1 | ⚠ See below |
| macOS AFP (Apple Filing Protocol) | Not Windows-supported | ✗ Not supported |

### SMBv1 note

Windows Server 2016 and later disable SMBv1 by default. If a NAS only supports SMBv1,
ioFTPD will log a specific message identifying the cause (see [Log Messages](#log-messages))
and recommend upgrading the NAS firmware to Samba 4.x.

To re-enable SMBv1 (not recommended): **Turn Windows features on or off →
SMB 1.0/CIFS File Sharing Support**.

---

## Log Messages

### Startup and recovery

| Log entry | Meaning |
|---|---|
| `Network mount connected: \\server\share` | Share is reachable; WNet connection established |
| `Network mount back online: \\server\share` | Share recovered after being offline |
| `Network mount offline: \\server\share` | Share has become unreachable |
| `Network mount: credential file reloaded` | `SITE REHASH` picked up changes to `netmounts.cfg` |

### Connection errors

| Log entry | What to do |
|---|---|
| `cannot find \\server\share — check server name and share path` | Verify server hostname resolves and share exists |
| `access denied to \\server\share — check username and password in etc\netmounts.cfg` | Wrong credentials, or share requires credentials that are not configured |
| `login failed for \\server\share — incorrect username or password` | Wrong username or password in `netmounts.cfg` |
| `cannot reach \\server\share — check network connectivity` | Network path to server is down |
| `no network available for \\server\share — service may have started before network` | ioFTPD started before the NIC was ready; it will retry automatically |
| `\\server\share requires SMBv1 which is disabled…` | NAS only supports SMBv1; upgrade NAS firmware or re-enable SMBv1 |
| `protocol error connecting to \\server\share — check server availability and SMB configuration` | Generic SMB protocol failure; check server logs |

---

## Rehash

`SITE REHASH` reloads `netmounts.cfg` without restarting ioFTPD:

- Credentials for existing shares are updated immediately.
- New shares added to `netmounts.cfg` are registered and their timers started.
- Active connections are not interrupted.
- The `Network_Check_Interval` and `Network_Max_Retry_Interval` values are also
  re-read; changes take effect on the next timer reschedule.

On success the log emits: `Network mount: credential file reloaded`

---

## Troubleshooting

**Share does not connect at startup**

1. Check the log for an error message from the table above.
2. Verify the UNC path in the `.vfs` file uses `\\server\share` notation and that the
   path is accessible from the ioFTPD service account.
3. If credentials are required, confirm the entry exists in `etc\netmounts.cfg` and
   that the path in `netmounts.cfg` matches the share root (e.g. `\\nas\media`, not the
   full subdirectory path `\\nas\media\movies`).

**Share works interactively but not when ioFTPD runs as a service**

ioFTPD runs in Session 0. Drive letters mapped in an interactive session are not visible
to services. Switch the `.vfs` entry to a UNC path directly.

**Updated credentials in `netmounts.cfg` have no effect**

Run `SITE REHASH`. Changes to `netmounts.cfg` are not picked up automatically — a rehash
or restart is required.

**Transfers fail immediately after a NAS comes back online**

ioFTPD's `NotifyAddrChange` watch thread should trigger a reconnect within seconds of
network recovery. If transfers still fail briefly, the inline reactive reconnect in
`IoCreateFile` will retry once transparently. If the issue persists, check that the
watch thread is running (look for the `NotifyAddrChange failed` log message at startup,
which would indicate the watch thread could not register).

**SMBv1 error on a Linux or NAS share**

Modern Linux Samba (4.x) supports SMBv2 and SMBv3 natively. If ioFTPD logs an SMBv1
message for a Linux share, the Samba configuration on the server may be restricting
it to SMBv1. Edit `/etc/samba/smb.conf` on the server and add:

```ini
[global]
min protocol = SMB2
```

Then restart Samba (`systemctl restart smbd`).
