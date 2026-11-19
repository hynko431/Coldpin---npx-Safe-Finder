---
last_reviewed: 2026-11-19
review_by: 2027-02-19
status: current
owner_lens: threat-taxonomy
sources: MITRE ATT&CK v19.1; MITRE ATLAS; MITRE D3FEND v1.4.0; NIST CSF 2.0; NIST AI RMF 1.0; DataDog GuardDog; OpenSSF Malicious Packages
---

# Threat Taxonomy & Static Detection Catalog

## 1. Framework Mapping

| Attack Class | MITRE ATT&CK / ATLAS | D3FEND / NIST CSF 2.0 | Deterministic Rule Code(s) |
|---|---|---|---|
| Hostile install lifecycle hooks (`preinstall`/`install`/`postinstall`) & manifest shell injection | `T1195.002`, `T1059.007` | Execution Isolation, `DE.CM-09` | `LIFECYCLE_HOOK_DANGEROUS_CMD`, `LIFECYCLE_HOOK_PRESENT`, `CHILD_PROCESS_DANGEROUS_EXEC`, `MANIFEST_SHELL_INJECTION_META` |
| Credential harvesting & exfiltration (`process.env`, `~/.npmrc`, `~/.ssh`, `~/.aws`) | `T1552.001`, `T1041` | `DE.CM-09`, `PR.PS-01` | `TAINT_CRED_TO_NETWORK_OR_EXEC`, `ENV_SERIALIZATION_EXFIL`, `CREDENTIAL_FILE_ACCESS`, `SHADY_WEBHOOK_OR_RAW_IP` |
| Obfuscation, Base64/Hex payloads, Unicode-escaped / computed `eval`, `_0x` obfuscators | `T1027`, `T1059.007` | `DE.AE-02` | `OBFUSCATED_DYNAMIC_EXEC`, `BASE64_PAYLOAD_SUSPICIOUS`, `HIGH_ENTROPY_OBFUSCATION` |
| Tarball-only supply-chain injection (Shai-Hulud / hijacked npm token) | `T1195.002`, `T1554` | `GV.SC-07`, `ID.RA-01` | `TARBALL_SOURCE_DRIFT_SCRIPTS`, `TARBALL_SOURCE_DRIFT_BIN`, `TARBALL_SOURCE_DRIFT_DEPS`, `TARBALL_SOURCE_DRIFT_FILE_MODIFIED`, `TARBALL_SOURCE_DRIFT_EXTRA_EXEC`, `TARBALL_ONLY_RELEASE_COMPROMISE` |
| Archive smuggling (Zip Slip, symlinks, PAX linkpath/malformed PAX, EOF polyglots, bad tar checksums, duplicate entries, NTFS collisions, zip bombs) | `T1546`, `T1499`, `T1195.002` | Application Hardening | `ARCHIVE_PATH_TRAVERSAL_OR_WINDOWS_HAZARD`, `ARCHIVE_UNSAFE_LINK_OR_DEVICE`, `ARCHIVE_CORRUPT_HEADER_CHECKSUM`, `ARCHIVE_MALFORMED_PAX_HEADER`, `ARCHIVE_EOF_POLYGLOT_SMUGGLING`, `ARCHIVE_DUPLICATE_ENTRY_DIFFERENTIAL`, `ARCHIVE_CASE_COLLISION`, `ARCHIVE_DECOMPRESSION_BOMB` |
| Typosquatting & AI slopsquatting | `T1195.002`, `T1608.001` | `ID.RA-09`, `GV.SC-03` | `TYPOSQUAT_OR_SLOPSQUAT_MATCH`, `SLOPSQUAT_YOUNG_WITH_HOOKS`, `RELEASE_COOLDOWN_QUARANTINE` |
| Dependency confusion (public shadowing internal namespaces) | `T1195.001` | `ID.RA-09`, `GV.SC-06` | `UNPINNED_PRIVATE_SCOPE`, `UNSCOPED_PRIVATE_PREFIX`, `CLAIMABLE_ON_PUBLIC_NPM`, `PUBLIC_SHADOW_EXISTS` |
| Indirect prompt injection & Trojan-Source Unicode spoofing | `AML.T0051.001`, `AML.T0054`, `T1027` | Content Validation, NIST AI RMF `MEASURE-2.7` | `HIDDEN_UNICODE_TROJAN_SOURCE`, `PROMPT_INJECTION_SIGNAL` |
| Native binary / WASM payload smuggling | `T1554`, `AML.T0010` | Platform Hardening | `NATIVE_OR_WASM_ARTIFACT` (triggers REA Tier-2 escalation) |

## 2. Seven Typosquatting Mutation Primitives

Implemented in `src/discovery/slopsquat-guard.ts` with a minimum-length guard (`>= 5` chars) to avoid false positives on short legitimate CLIs (`tsx`, `zx`, `bun`):

1. **Transposition:** `loadsh` -> `lodash`
2. **Omission:** `esint` -> `eslint`
3. **Repetition:** `esllint` -> `eslint`
4. **Delimiter swap:** `crossenv` -> `cross-env`
5. **Word order swap:** `env-cross` -> `cross-env`
6. **Homoglyph substitution:** `es1int` -> `eslint`
7. **Suffix / brandjack:** `lodash-js` -> `lodash`
