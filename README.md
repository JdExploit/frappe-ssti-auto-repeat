# frappe-ssti-auto-repeat

**Server-Side Template Injection (SSTI) in Frappe / ERPNext "Auto Repeat" message preview leading to unauthorized database read**

A low-privilege authenticated user — holding only the business role **Accounts User / Accounts Manager** — can have arbitrary Jinja templates evaluated on the server and read database rows across the permission boundary.

> Coordinated disclosure. This repository publishes the technical analysis and the fix guidance **only**. An executable proof-of-concept is intentionally **not** included and is shared privately with the vendor and the CNA.

## Summary

| | |
|---|---|
| Vendor | Frappe Technologies |
| Product | Frappe Framework / ERPNext |
| Affected | Frappe Framework `16.52.0` and `17.0.0-dev` (develop). Believed to affect all versions shipping the Auto Repeat message preview (v13+). |
| Tested on | `frappe/erpnext:v16.51.1` (Frappe `16.52.0`), official Docker image |
| Class | CWE-1336 → CWE-863 → CWE-200 |
| Auth | Required, low privilege (`Accounts User`) |
| Impact | Confidentiality (High) — unauthorized read of database rows |
| CVSS 3.1 | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5 Medium) |

## The flaw in one paragraph

The whitelisted endpoint `generate_message_preview` renders two **user-controlled** fields (`Auto Repeat.message` / `.subject`) as **Jinja templates on the server** and returns the rendered output to the caller. On save only a Jinja **syntax** check runs. Although rendering uses `restrict_globals=True`, that "restricted" global set still exposes `frappe.get_all` (which forces `ignore_permissions=True`), raw `frappe.db.sql` and unchecked `frappe.db.get_value`. Result: arbitrary database read from a business role.

## Documentation

- [`docs/ADVISORY.md`](docs/ADVISORY.md) — full technical advisory (root cause, code, boundary, verification, fix).

## Verified behaviour (summary)

Dynamic testing against `frappe/erpnext:v16.51.1` with a user holding only `Accounts User`:

1. `message = {{ 1337*7 }}` → preview returned `9359` (server-side template evaluation).
2. A loop over `frappe.get_all("User", ...)` returned rows from `tabUser` that the role cannot read.
3. `{{ frappe.db.sql(...) }}` executes raw `SELECT` without DocType permission checks.

## Disclosure status

- [x] Disclosed to the vendor (Frappe security team).
- [ ] CVE assigned.
- [ ] Vendor fix.

## License

This advisory text is provided for defensive and disclosure purposes. See [`LICENSE`](LICENSE).
