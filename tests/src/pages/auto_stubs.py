# Auto-generated stubs (do not edit by hand)
import re

def _fallback_call(fn_name, page, *args):
    try:
        if fn_name.startswith("click_"):
            label = fn_name[len("click_"):].replace("_", " ").strip()
            try:
                page.get_by_role("button", name=re.compile(label, re.I)).first.click(); return
            except Exception: pass
            try:
                page.get_by_role("link", name=re.compile(label, re.I)).first.click(); return
            except Exception: pass
            page.get_by_text(re.compile(label, re.I)).first.click(); return

        if fn_name.startswith("enter_"):
            label = fn_name[len("enter_"):].replace("_", " ").strip()
            value = args[0] if args else ""
            try:
                page.get_by_label(re.compile(label, re.I)).fill(value); return
            except Exception: pass
            try:
                page.get_by_placeholder(re.compile(label, re.I)).fill(value); return
            except Exception: pass
            tb = page.get_by_role("textbox")
            if tb.count() > 0:
                tb.nth(tb.count()-1).fill(value); return

        if fn_name.startswith("select_"):
            label = fn_name[len("select_"):].replace("_", " ").strip()
            value = args[0] if args else ""
            try:
                sel = page.get_by_label(re.compile(label, re.I))
                sel.select_option(label=value); return
            except Exception: pass
            try:
                page.get_by_role("combobox", name=re.compile(label, re.I)).first.click()
                page.get_by_role("option", name=re.compile(value, re.I)).first.click(); return
            except Exception: pass
    except Exception as e:
        print(f"[AUTO-STUBS] Fallback failed for {fn_name}: {e!r}")
def click_add_new_customer(page):
    return _fallback_call('click_add_new_customer', page)

def click_customer(page):
    return _fallback_call('click_customer', page)

def click_new_customer(page):
    return _fallback_call('click_new_customer', page)

def enter_address(page, value):
    return _fallback_call('enter_address', page, value)

def enter_annual_income(page, value):
    return _fallback_call('enter_annual_income', page, value)

def enter_email(page, value):
    return _fallback_call('enter_email', page, value)

def enter_full_name(page, value):
    return _fallback_call('enter_full_name', page, value)

def enter_initial_deposit(page, value):
    return _fallback_call('enter_initial_deposit', page, value)

def enter_occupation(page, value):
    return _fallback_call('enter_occupation', page, value)
