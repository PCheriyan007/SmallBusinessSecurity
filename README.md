<h1>Endpoint Security Modernization for Small Business Client</h1>

Independent security project delivered for a small business client to modernize endpoint security, identity management, and SaaS access governance, on a limited budget and without a dedicated EDR platform.

<h2>Overview</h2>

The client's environment relied on local Windows accounts with standing administrative privileges, no centralized patch management, minimal SaaS access controls, and no endpoint detection and response (EDR) capability. This project addressed each of those gaps using existing, low-cost tooling (Action1, Google Workspace, native Windows security features) rather than introducing expensive new platforms.

**Environment:** 9 Windows 11 endpoints, Google Workspace as the identity and productivity backbone.

<h2>Skills Demonstrated</h2>

- Vulnerability & patch management
- Identity and access management (IAM), least-privilege enforcement
- SaaS security posture management (OAuth app governance)
- Security automation and scripting (PowerShell, AI-assisted development with manual review)
- EDR-adjacent detection and alerting
- Endpoint and browser hardening

<h2>Vulnerability & Patch Management</h2>

- Deployed Action1 vulnerability and patch management software across 8 Windows 11 endpoints.
- <b>Day 1:</b> Resolved 83 overdue software updates and reduced identified vulnerabilities from 3,804 to 0 through patching and removal of vulnerable software.

<h2>Identity & Access Management</h2>

- Migrated endpoint logins from local user accounts (many with standing administrative privileges) to centralized authentication via Google Credential Provider for Windows, tied to existing Google Workspace accounts.
- Associated migrated accounts with existing user profiles to preserve data continuity during the transition.
- Implemented Admin by Request to centralize and enforce least-privilege access, replacing standing local admin rights.
- Configured SSO login for admin staff via Admin by Request, tied to Google Workspace identity (additional application SSO rollouts planned as the organization's broader app inventory is identified).
- Migrated previously shared email addresses to Google Groups, configuring group-level permissions and assigning users accordingly.
- Configured Collaborative Inboxes where applicable to support shared team workflows.

<h2>SaaS Security Posture / Google Workspace Administration</h2>

- Audited Google Workspace API Controls, reviewing third-party OAuth application access across the organization.
- Blocked unapproved third-party applications and set trust levels for approved ones.
- Disabled unrestricted app-authorization permissions, limiting default third-party app access to Google Sign-On identity data only.
- Routed further application access requests through admin approval rather than default user self-service.
- Deployed and enrolled managed Chrome browsers across endpoints, enforcing login requirements, session limits, and browser configuration policies.

<h2>Detection & Alerting</h2>

- Configured [automated email alerting on Windows Defender detection/response events (Event ID 1116/1117)](/DefenderAlert.ps1) via Action 1.
  - [Uninstall Script](/DefenderAlert-Uninstall.ps1)
- Goal: extend EDR-adjacent incident response capability in an environment without a dedicated EDR platform, at no added licensing cost.

<img width="2170" height="525" alt="image" src="https://github.com/user-attachments/assets/3c26c0c9-47c4-4e15-b204-8175494b7cc5" />


<h2>Security Automation (PowerShell / Action1)</h2>

Designed and deployed a suite of custom PowerShell scripts in Action1 (AI-assisted development, manually reviewed and validated for syntax and logic) covering:

- [Endpoint network isolation](/IsolateEndpoint.ps1) (excluding IPs/ports required for Action1 connectivity)
- [Endpoint network reconnection](/ReleaseEndpoint.ps1)
- [On-demand Windows Defender Quick Scan](/DefenderQuickScan.ps1)
- [On-demand Windows Defender Full Disk Scan](/DefenderFullScan.ps1)
- [Stopping any active Windows Defender Scans](/DefenderStopScan.ps1)
- [Automated managed Chrome browser deployment and enrollment](/DeployManagedChrome.ps1), replacing a manual, per-machine process

All scripts have email reporting (piggybacks off of the email alerting set up for Windows Defender) built in to alert designated admin staff via email.

<img width="651" height="534" alt="image" src="https://github.com/user-attachments/assets/30950a14-c688-417f-925b-e2e368b83419" />


<h2>Tooling</h2>

- **Action1**
  - Vulnerability management, patch management, script deployment
- **Admin by Request**
  - Centralized privileged-access management and enforcement
- **Google Workspace Admin Console**
  - Identity, Conditional Access, API controls, Chrome Browser management
- **Windows Defender**
  - Endpoint scanning and detection
- **Claude / Gemini**
  - AI-assisted script development (all code manually reviewed and validated before deployment)

---

*Client details have been anonymized. This project was performed as independent security consulting work.*
