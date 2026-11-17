# Standard UI/UX Guide — Advanced XDR

**Version:** 1.3\
**Date:** 2026-11-17\
**Status:** Baseline for GUI development

## 1. Purpose and Scope

This is the GUI baseline for interactions, content, design tokens, accessibility,
responsive layouts, and UI verification. Architecture and authorization decisions
are kept in [PROJECT_ARCHITECTURE.md](PROJECT_ARCHITECTURE.md). Capability
requirements and validation criteria are kept in [XDRCapabilities.md](XDRCapabilities.md).

## 2. Loop Instruction for GUI Updates

Read this guide before each GUI update or upgrade, then follow the project's
shared loop. Review the affected screens and components, reuse their established
patterns, and apply the GUI checks in section 17. Record verification results
with the update. Restore access before editing the GUI if this guide is unavailable.
Revise this guide when the GUI standard changes.
[Project update loop](PROJECT_ARCHITECTURE.md#loop-instruction-for-project-updates)

## 3. Product Principles
- **Analyst-first:** Optimize for rapid SOC triage, investigation, threat hunting, and response.
- **Evidence-first:** Distinguish observed telemetry from correlation, inference, and AI suggestions.
- **Safe by default:** High-impact response actions require explicit scope and confirmation.
- **Consistent:** Reuse common terminology, patterns, and components.
- **Accessible:** Target WCAG 2.2 AA.
- **Traceable:** Show data provenance, timestamps, detection source, and audit history.
- **Honest:** Do not imply unverified MITRE ATT&CK coverage or guaranteed protection.

## 4. Users and Permissions

Use the three application roles and action permissions defined in the
architecture. Treat SOC tiers and job titles as personas. Render affordances
from authorized server capabilities and apply the UX rules below.
[Architecture RBAC matrix](PROJECT_ARCHITECTURE.md#role-based-access-control)

### Enforcement and UX Rules
1. Use the server's authorization result for UI affordances and feedback.
2. Apply least privilege and scope permissions by tenant, asset, or data classification where applicable.
3. Use the server permission definition for routes, navigation, buttons, API access, and tests. Deny by default.
4. Viewer interfaces must not display enabled create, edit, delete, deploy, or execute controls.
5. Show a clear **Access denied** state for unauthorized direct links. Keep protected content out of the error state.
6. Require explicit confirmation, policy approval where configured, and audit records for disruptive or destructive response actions—even for Admin.
7. Record actor, role, target, time, action, outcome, and approval details for privileged operations.
8. Test all three roles on every new or modified GUI feature, including direct URL and API access.

## 5. Information Architecture
Target navigation for supported capabilities. Keep the active release navigation aligned with the architecture milestones.
1. SOC Overview
2. Alerts
3. Incidents
4. Investigations / Timelines
5. Threat Hunting
6. MITRE ATT&CK Coverage
7. Detection Rules
8. Assets / Endpoints
9. Identities
10. Network
11. Email
12. Cloud / SaaS / Containers
13. Threat Intelligence
14. Response / Playbooks
15. Reports / Audit
16. Settings / Integrations

Use clear page titles, a consistent sidebar, in-content links to parent views, persistent search and filter context, and a visible active location.

## 6. Design System and Tokens
- Define reusable tokens for color, typography, spacing, elevation, radius, and breakpoints.
- Spacing baseline: 4px grid; prefer 4, 8, 12, 16, 24, and 32px.
- Default body text: 14–16px; compact labels no smaller than 12px where feasible.
- Use a system sans-serif font unless the project establishes a brand font.
- Support light/dark modes when implemented; ensure readable contrast in each.
- Semantic statuses: Critical, High, Medium, Low, Informational, Success, Warning, Error, Neutral.
- Severity must always have a text label; color alone is insufficient.
- Target text contrast >=4.5:1, large text >=3:1, and applicable UI controls >=3:1.
- Avoid one-off inline styles and duplicated design constants.

## 7. Layout and Responsive Rules
- Desktop-first for dense analyst workflows, but tablet and narrow-screen views must remain usable.
- Use centralized responsive breakpoints and a collapsible navigation sidebar.
- Allow wide tables to scroll without clipping controls or concealing the selected row.
- Keep primary actions discoverable, including under zoom and reflow.
- Never truncate critical evidence without a way to inspect the full value.

## 8. Reusable Component Requirements
- **Buttons:** One obvious primary action per context; destructive actions visibly distinct.
- **Forms:** Visible labels, validation, inline errors, and clear confirmation.
- **Tables:** Sort, filter, pagination/virtualization where needed, column configuration, and accessible row actions.
- **Search:** Query guidance, active filter chips, clear/reset, and no-result explanations.
- **Dialogs/Drawers:** Proper focus management, descriptive actions, and keyboard support.
- **Charts:** Axis labels, units, date range, legend, and accessible text/table alternatives.
- **Notifications:** Clearly differentiate information, warning, error, and confirmed success.
- **Entity links:** Consistent navigation among users, devices, IPs, processes, alerts, and incidents.

## 9. Security-Specific Data Presentation
- Treat **severity**, **confidence**, **priority**, and **incident status** as distinct fields.
- Show timestamps with timezone; preserve original event time and ingestion time when available.
- Display MITRE ATT&CK tactic, technique ID, technique name, and official reference link.
- Show detection rule ID, data source, sensor, evidence, and correlation reason.
- Flag missing telemetry, stale data, unsupported integrations, and incomplete analysis.
- Distinguish `Native`, `Integrated`, `Custom`, `Partial`, and `Unsupported` capabilities.
- Never treat ATT&CK technique mapping as proof that detection is effective.

## 10. Target XDR Screen Patterns
### SOC Dashboard
Alert/incident trends, severity and status distribution, ingestion health, relevant KPIs, and drill-downs. Explain MTTD/MTTR calculation windows.
### Alerts
Searchable alert queue with severity, confidence, source, affected entities, ATT&CK mapping, time, assignee, and disposition.
### Incidents
Correlated alerts, timeline, evidence, affected assets, investigation notes, status, owner, and response history.
### Investigation
Chronological event timeline, process tree or entity relationships where available, raw evidence, and investigation pivots.
### Threat Hunting
Query editor, schema hints, time-range controls, saved queries, query errors, and controlled export.
### MITRE ATT&CK Coverage
Tactic/technique matrix with mapped detections, required telemetry, readiness, last validation, and coverage gaps.
### Detection Engineering
Rule metadata, detection logic, test cases, tuning, approvals, versioning, deployment state, and rollback.
### Response Center
Playbooks, action scopes, approvals, execution progress, outcomes, and immutable audit trail where supported.
### Integrations
Connector health, last successful ingestion, lag, permission scopes, and failure guidance.

## 11. Response and Destructive Action Safety
- Categorize actions as informational, reversible, disruptive, or destructive.
- For host isolation, account disablement, token revocation, quarantine, or bulk actions: show exact targets, expected impact, permission requirements, and explicit confirmation.
- Support policy-based approvals and role restrictions.
- Show `Requested`, `Pending Approval`, `Running`, `Succeeded`, `Failed`, `Partially Succeeded`, and `Rolled Back` as appropriate.
- Do not report success until the backend confirms it.
- Protect against duplicate submissions; provide action history and retry guidance.

## 12. Mandatory Screen States
Every data-driven screen must handle: loading, empty dataset, no search results, partial/missing telemetry, permission denied, error/retry, stale data, success, and disconnected state when relevant.
Never present mock data as live telemetry.

## 13. Accessibility and Usability
- Target WCAG 2.2 AA, including keyboard navigation, visible focus, proper labels, semantic headings, and screen-reader support.
- Do not rely on hover or color alone.
- Announce meaningful asynchronous status changes.
- Respect reduced-motion preferences.
- Ensure critical workflows remain usable at 200% zoom.

## 14. Performance and Reliability
- Use server-side pagination and filtering for large event volumes where appropriate.
- Virtualize long result lists carefully without breaking accessibility.
- Show last refresh time; avoid unexpectedly resetting analyst selection or filters.
- Debounce costly searches; support retries and cancellation.
- Define measurable page-performance budgets after profiling real workloads.

## 15. Security and Privacy
- Treat security events, identities, logs, evidence, credentials, and tokens as sensitive.
- Escape attacker-controlled text and never execute raw HTML from telemetry.
- Apply server-side authorization to every read and response action.
- Minimize sensitive data in browser storage, client bundles, and application logs.
- Respect tenant isolation, retention rules, and audit requirements.

## 16. Content and Terminology
- Use concise, unambiguous language and consistent labels.
- Distinguish detection, prevention, investigation, and response.
- Use actionable errors that explain the next step without exposing secrets.
- Label AI-generated summaries and allow users to inspect underlying evidence.

## 17. QA / Definition of Done
For every GUI change, confirm:
- [ ] Read `Standard_UIUX.md` before implementation.
- [ ] Reviewed existing design patterns and affected workflows.
- [ ] Reused shared tokens and components.
- [ ] Verified main flow and edge cases.
- [ ] Verified loading, empty, error, permission, and stale states.
- [ ] Checked responsive behavior and keyboard accessibility.
- [ ] Verified timestamps, statuses, severity, and ATT&CK mappings.
- [ ] Tested backend authorization and high-impact action safeguards.
- [ ] Verified Admin, Analyst, and Viewer access including direct links and API authorization.
- [ ] Preserved evidence provenance and auditability.
- [ ] Ran relevant automated/manual tests and recorded results.
- [ ] Updated related documentation and approved deviations.

## 18. Change Control
1. Propose the change and explain its rationale.
2. Identify affected components, screens, and migration risks.
3. Get project owner approval for material changes.
4. Increment the version and update the change log.
5. Update components, tests, and docs consistently.

| Version | Date | Change | Approval |
|---|---|---|---|
| 1.0 | 2026-11-15 | Initial XDR UI/UX standard and mandatory development loop | Pending review |
| 1.1 | 2026-11-15 | Restrict initial application roles to Admin, Analyst, Viewer; define RBAC matrix and enforcement rules | User-directed |
| 1.2 | 2026-11-15 | Link the GUI baseline to the shared project loop and architecture-owned permissions | User-directed |
| 1.3 | 2026-11-17 | Keep Operations as the only top navigation label | User-directed |


## Locked Global Footer

The PersistGuard GUI must render the same non-editable footer on every route, through the shared application layout rather than per-page copies.

- Exact first line: `Cybersecurity is everyone Responsibility`
- Exact second-line prefix: `Powered by: apm @ ` followed by the current calendar year.
- The year must refresh automatically while the browser remains open across a year boundary.
- The footer stays at the bottom of the viewport when content is short, remains visible while scrolling, and adapts to narrow screens without obscuring content.
- The dashboard scrollbar ends at the top edge of the footer. The footer spans the full viewport width below the scrolling region.
- Only a reviewed source-code change may modify the locked wording or remove the footer; it is not configurable through dashboard settings.



## Locked Sidebar and Top Navigation

Preserve the original dashboard layout, page content sizing, and spacing within the scrolling region. Keep page content top-aligned and reachable at each breakpoint.

- Desktop sidebar remains anchored using sticky positioning. Its navigation list scrolls when the viewport is too short to show all links.
- Top navigation remains visible using sticky positioning.
- The top navigation displays `Operations` and the API connection control. Each view displays its title in the content area.
- Footer wording and year behavior remain unchanged.
- Responsive navigation keeps its original sizing and wrapping; avoid clipping links.
- Navigation branding and placement are not editable through user-facing GUI settings.
- Validate desktop and mobile screenshots and long-content scrolling before declaring the layout verified.

