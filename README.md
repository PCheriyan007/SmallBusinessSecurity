# Endpoint Security Modernization for Small Business Client

Independent security project delivered for a small business client to modernize endpoint security, identity management, and SaaS access governance, on a limited budget and without a dedicated EDR platform.

## Overview

The client's environment relied on local Windows accounts with standing administrative privileges, no centralized patch management, minimal SaaS access controls, and no endpoint detection and response (EDR) capability. This project addressed each of those gaps using existing, low-cost tooling (Action1, Google Workspace, native Windows security features) rather than introducing expensive new platforms.

**Environment:** 9 Windows 11 endpoints, Google Workspace as the identity and productivity backbone.

## Skills Demonstrated

- Vulnerability & patch management
- Identity and access management (IAM), least-privilege enforcement
- SaaS security posture management (OAuth app governance)
- Security automation and scripting (PowerShell, AI-assisted development with manual review)
- EDR-adjacent detection and alerting
- Endpoint and browser hardening

---

## Vulnerability & Patch Management

- Deployed Action1 vulnerability and patch management software across 8 Windows 11 endpoints.
- Resolved 83 overdue software updates.
- Reduced identified vulnerabilities from 3,804 to 0 through patching and removal of vulnerable software.

## Identity & Access Management

- Migrated endpoint logins from local user accounts (many with standing administrative privileges) to centralized authentication via Google Credential Provider for Windows, tied to existing Google Workspace accounts.
- Associated migrated accounts with existing user profiles to preserve data continuity during the transition.
- Implemented Admin by Request to centralize and enforce least-privilege access, replacing standing local admin rights.
- Configured SSO login for admin staff via Admin by Request, tied to Google Workspace identity (additional application SSO rollouts planned as the organization's broader app inventory is identified).
- Migrated previously shared email addresses to Google Groups, configuring group-level permissions and assigning users accordingly.
- Configured Collaborative Inboxes where applicable to support shared team workflows.

## SaaS Security Posture / Google Workspace Administration

- Audited Google Workspace API Controls, reviewing third-party OAuth application access across the organization.
- Blocked unapproved third-party applications and set trust levels for approved ones.
- Disabled unrestricted app-authorization permissions, limiting default third-party app access to Google Sign-On identity data only.
- Routed further application access requests through admin approval rather than default user self-service.
- Deployed and enrolled managed Chrome browsers across endpoints, enforcing login requirements, session limits, and browser configuration policies.

## Security Automation (PowerShell / Action1)

Designed and deployed a suite of custom PowerShell scripts in Action1 (AI-assisted development, manually reviewed and validated for syntax and logic) covering:

- [Endpoint network isolation](/IsolateEndpoint.ps1) (excluding IPs/ports required for Action1 connectivity)
- [Endpoint network reconnection](/ReleaseEndpoint.ps1)
- On-demand Windows Defender Quick Scan
- On-demand Windows Defender Full Disk Scan
- [Automated managed Chrome browser deployment and enrollment](/DeployManagedChrome.ps1), replacing a manual, per-machine process

## Detection & Alerting *(in progress)*

- Configuring [automated email alerting on Windows Defender detection/response events (Event ID 1116/1117)](/DefenderAlert.ps1) via Action 1.
  - [Uninstall Script](/DefenderAlert-Uninstall.ps1)
- Currently validating email alerting.
- Goal: extend EDR-adjacent incident response capability in an environment without a dedicated EDR platform, at no added licensing cost.

## Tooling

- **Action1**
  - Vulnerability management, patch management, script deployment
- **Google Workspace Admin Console**
  - Identity, API controls, Chrome management
- **Windows Defender**
  - Endpoint scanning and detection
- **Claude / Gemini**
  - AI-assisted script development (all code manually reviewed and validated before deployment)

---

*Client details anonymized. This project was performed as independent security consulting work.*
