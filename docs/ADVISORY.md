# ADVISORY — SSTI in Frappe / ERPNext "Auto Repeat" message preview

**Product:** Frappe Framework (affects ERPNext, HRMS, CRM and every Frappe-based app)
**Component:** `frappe/automation/doctype/auto_repeat/auto_repeat.py` — `generate_message_preview`
**Class:** CWE-1336 (Template Engine Neutralization) → CWE-863 (Incorrect Authorization) → CWE-200 (Sensitive Information Exposure)
**Severity:** High — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (6.5)
**Tested on:** ERPNext `16.51.1`, Frappe `16.52.0` (image `frappe/erpnext:v16.51.1`); code audit on Frappe `17.0.0-dev` develop `b3f4e4551f3ea3f1e53dd5bf622d97752aeb2587`.

---

## 1. Summary

The whitelisted endpoint
`frappe.automation.doctype.auto_repeat.auto_repeat.generate_message_preview`
renders two user-controlled text fields (`Auto Repeat.message` and `Auto Repeat.subject`)
as Jinja templates on the server and returns the result to the caller.

The business role **Accounts User** (or **Accounts Manager**) can create/write an `Auto Repeat`.
No administrative privilege is required.

Rendering uses `restrict_globals=True`, treated as a boundary — it is not: the restricted set
(`render_safe_globals()`) exposes `frappe.get_all` with `ignore_permissions=True`, raw
`frappe.db.sql` and unchecked `frappe.db.get_value`. A low-privilege user can therefore read
arbitrary rows from any table.

---

## 2. Vulnerable code

`frappe/automation/doctype/auto_repeat/auto_repeat.py:634-645` (develop)

```python
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
```

Syntax-only validation on save (`:92-93`):

```python
validate_template(self.subject or "")
validate_template(self.message or "")
```

`frappe/utils/jinja.py:96-108`

```python
def validate_template(html, restrict_globals=None):
    """Throws exception if there is a syntax error in the Jinja Template"""
    ...
    jenv = get_jenv(restrict_globals=restrict_globals)
    try:
        jenv.from_string(html)
    except TemplateSyntaxError as e:
        frappe.throw(f"Syntax error in template as line {e.lineno}: {e.message}")
```

## 3. Why `restrict_globals=True` is not a boundary

`frappe/utils/safe_exec.py:506-638`

```python
get_list=safe_get_list,
get_all=safe_get_all,                 # :554
...
db=NamespaceDict(
    get_list=safe_get_list,
    get_all=safe_get_all,
    get_value=safe_get_value,
    get_single_value=safe_get_single_value,
    ...
    sql=read_sql,                     # :592
),
```

`frappe/utils/safe_exec.py:306-311`

```python
def safe_get_all(*args, **kwargs):
    kwargs["ignore_permissions"] = True
    if "limit_page_length" not in kwargs:
        kwargs["limit_page_length"] = 0
    return safe_get_list(*args, **kwargs)
```

`frappe/utils/safe_exec.py:847-851`

```python
def read_sql(query, *args, **kwargs):
    """a wrapper for frappe.db.sql to allow reads"""
    query = str(query)
    check_safe_sql_query(query)       # only rejects `into outfile/dumpfile`
    return frappe.db.sql(query, *args, **kwargs)
```

## 4. Authorization boundary

`frappe/automation/doctype/auto_repeat/auto_repeat.json` permissions:

| Role | create | write | read | delete |
|---|---|---|---|---|
| System Manager | 1 | 1 | 1 | 1 |
| Accounts Manager | 1 | 1 | 1 | 1 |
| Accounts User | 1 | 1 | 1 | 1 |

`generate_message_preview` requires only `has_permission("Auto Repeat", "write")`.

## 5. Verification (summary)

Dynamic testing against `frappe/erpnext:v16.51.1`, account with only `Accounts User`:

1. `message = {{ 1337*7 }}` → preview HTTP 200 `{"message":{"message":"9359",...}}`.
2. `{% for u in frappe.get_all("User", fields=["name"], limit_page_length=0) %}{{ u.name }}{% endfor %}`
   → returned `attacker@example.com`, `Guest`, `Administrator` (rows the role cannot read).
3. `{{ frappe.db.sql("select ... from tabUser", as_dict=True) }}` → raw SELECT.

> Frappe redacts some password-type fields (`api_secret`) at the ORM/API layer. This is an
> independent defence and is not relied upon in this advisory.

## 6. Suggested fix

Do not compile attacker-controlled fields as templates. Render an explicit, fixed set of
document placeholders in `generate_message_preview`, restricted to administrators.
Additionally, `render_safe_globals()` should not expose `frappe.get_all` with
`ignore_permissions=True`, raw `frappe.db.sql`, or unchecked `frappe.db.get_value` to templates
authored by non-administrators.

## 7. References (code, develop `b3f4e45`)

- `frappe/automation/doctype/auto_repeat/auto_repeat.py:634-645`
- `frappe/automation/doctype/auto_repeat/auto_repeat.py:92-93`
- `frappe/automation/doctype/auto_repeat/auto_repeat.json` (permissions)
- `frappe/utils/jinja.py:96-108`
- `frappe/utils/safe_exec.py:306-311`, `:506-638`, `:554`, `:592`, `:847-851`
