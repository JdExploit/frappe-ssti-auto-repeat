# VulDB — entry fields (corrected)

The previously pasted form used Microsoft / Windows / buffer overflow by mistake. Use the
values below for this entry (Frappe / ERPNext SSTI).

## Proveedor
Frappe Technologies

## Producto
Frappe Framework / ERPNext

## Versión o Commit
16.52.0 / 17.0.0-dev (develop b3f4e4551f3ea3f1e53dd5bf622d97752aeb2587)

## Vulnerabilidad
Server-Side Template Injection (SSTI)

## Descripción (markup disabled, <= 9000 chars)

```
Server-Side Template Injection (SSTI) in Frappe / ERPNext "Auto Repeat" message preview leading to unauthorized database read.

The whitelisted endpoint frappe.automation.doctype.auto_repeat.auto_repeat.generate_message_preview renders two user-controlled text fields (Auto Repeat.message and Auto Repeat.subject) as Jinja templates on the server and returns the rendered output to the caller. On save, only a Jinja syntax check is performed (validate_template), which does not block template expressions or access to the frappe object.

Any user able to create/write an "Auto Repeat" document controls those fields. The business roles "Accounts User" and "Accounts Manager" have create/write on Auto Repeat by default, so no administrative privilege is required.

Rendering uses restrict_globals=True, which is treated as a confidentiality boundary but is not: the restricted global set (render_safe_globals) still exposes:
- frappe.get_all -> safe_get_all, which forces ignore_permissions=True and limit_page_length=0;
- frappe.db.sql -> read_sql, i.e. raw SELECT/EXPLAIN;
- frappe.db.get_value -> safe_get_value, raw DB access with no permission check.

As a result, a low-privilege authenticated user can read arbitrary rows from any table, crossing the permission boundary.

AFFECTED CODE (Frappe 17.0.0-dev, develop b3f4e45):
frappe/automation/doctype/auto_repeat/auto_repeat.py:634-645

    @frappe.whitelist(methods=["POST"])
    def generate_message_preview(name: str):
        frappe.has_permission("Auto Repeat", "write", throw=True)
        auto_repeat = frappe.get_doc("Auto Repeat", str(name))
        doc = frappe.get_doc(auto_repeat.reference_doctype, auto_repeat.reference_document)
        doc.check_permission()
        subject_preview = _("Please add a subject to your email")
        msg_preview = frappe.render_template(auto_repeat.message, {"doc": doc}, restrict_globals=True)
        if auto_repeat.subject:
            subject_preview = frappe.render_template(auto_repeat.subject, {"doc": doc}, restrict_globals=True)
        return {"message": msg_preview, "subject": subject_preview}

On stable 16.51.1 the same function is at :637-647 and calls frappe.render_template(auto_repeat.message, {"doc": doc}) with default restrict_globals (restricted set), so behaviour is identical.

Syntax-only validation on save (auto_repeat.py:92-93):
    validate_template(self.subject or "")
    validate_template(self.message or "")

RESTRICTED GLOBALS ARE NOT A CONFIDENTIALITY BOUNDARY (safe_exec.py):
:306-311  safe_get_all forces kwargs["ignore_permissions"] = True
:554      get_all=safe_get_all
:592      sql=read_sql
:847-851  read_sql -> check_safe_sql_query only rejects "into outfile/dumpfile"; any SELECT is allowed

AUTHORIZATION: generate_message_preview only requires has_permission("Auto Repeat","write"), satisfied by the business roles Accounts User/Accounts Manager (auto_repeat.json grants them create/write).

VERIFICATION (dynamic, image frappe/erpnext:v16.51.1, Frappe 16.52.0; account with only "Accounts User"):
1. message = {{ 1337*7 }} -> preview HTTP 200 {"message":{"message":"9359","subject":"x"}} (server-side template evaluation confirmed).
2. {% for u in frappe.get_all("User", fields=["name","api_key","api_secret","enabled"], limit_page_length=0) %}{{ u.name }}|{{ u.api_key }}|{{ u.api_secret }}|{{ u.enabled }}{% endfor %} -> returned rows from tabUser (attacker@example.com, Guest, Administrator) that the role cannot read.
3. {{ frappe.db.sql("select name from tabUser", as_dict=True) }} -> executes raw SELECT without DocType permission checks.

IMPACT: authenticated low-privilege user -> unauthorized read of database rows across the permission boundary (CWE-1336 -> CWE-863 -> CWE-200).

PROPOSED CVSS 3.1: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (6.5 Medium).

SUGGESTED FIX: do not compile attacker-controlled fields as templates. Render an explicit, fixed set of document placeholders in generate_message_preview. Do not expose frappe.get_all (ignore_permissions=True), raw frappe.db.sql, or unchecked frappe.db.get_value to templates authored by non-administrators.
```

## Aviso / Explotación
https://github.com/<tu-usuario>/frappe-ssti-auto-repeat

(Advisory público sin PoC ejecutable; PoC privado compartido con el vendor/CNA.)

## Request a CVE
Prerequisites: (1) vendor contacted beforehand — SÍ (guardar el email y el acuse);
(2) no CVE assigned yet — SÍ;
(3) not submitted to another CNA — SÍ.
