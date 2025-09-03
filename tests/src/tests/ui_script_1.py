# Auto-generated UI runner

import sys, os, json, re, time
from pathlib import Path
from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

_THIS_FILE = Path(__file__).resolve()
_SRC_ROOT  = _THIS_FILE.parents[1]
if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))

# Also add the project root (the one that contains 'services') to sys.path
try:
    for p in _THIS_FILE.parents:
        if (p / "services").is_dir():
            _REPO_ROOT = p
            if str(_REPO_ROOT) not in sys.path:
                sys.path.insert(0, str(_REPO_ROOT))
            print(f"services path {_REPO_ROOT}")
            break
except Exception:
    pass

from lib.smart_ai import patch_page_with_smartai

from pages.auto_stubs import *
try:
    from pages.base_page import *
except Exception:
    pass
try:
    from pages.restful_page import *
except Exception:
    pass
from pages.auto_stubs import *
from pages.base_page import *
from pages.customer2_page import *
from pages.custoomer1_page import *
from pages.dashboard_page import *
# ----------------------------
# Speed + SmartAI-first helpers
# ----------------------------
def _speed_conf():
    # UI_SPEED: fast|medium|slow  (default medium)
    sp = os.getenv("UI_SPEED", "medium").lower().strip()
    if sp not in ("fast","medium","slow"):
        sp = "medium"
    # UI_TYPING_DELAY override (ms/char)
    if os.getenv("UI_TYPING_DELAY"):
        try:
            delay = max(0, int(os.getenv("UI_TYPING_DELAY")))
        except Exception:
            delay = 12 if sp == "medium" else (0 if sp == "fast" else 35)
    else:
        delay = 12 if sp == "medium" else (0 if sp == "fast" else 35)
    # settle time after a field is filled (ms)
    settle = 120 if sp == "medium" else (40 if sp == "fast" else 280)
    return delay, settle

def _all_contexts(page):
    yield page
    try:
        for fr in page.frames:
            yield fr
    except Exception:
        pass

def _visible_first(loc):
    try:
        vis = loc.filter(":visible")
        return vis.first if vis.count() > 0 else (loc.first if loc.count() > 0 else None)
    except Exception:
        return None

def _type_fill(loc, value: str, delay_ms: int):
    # medium-speed typing to satisfy controlled inputs
    text = "" if value is None else str(value)
    try:
        loc.click(timeout=2000)
    except Exception:
        pass
    try:
        loc.fill("", timeout=2000)
    except Exception:
        pass
    try:
        loc.type(text, delay=delay_ms)
    except Exception:
        # fallback to JS set if typing fails
        try:
            loc.evaluate(
                """(el, v) => {
                    const isInput = el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA');
                    if (isInput) {
                        const d = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value') ||
                                  Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value');
                        if (d && d.set) d.set.call(el, String(v)); else el.value = String(v);
                    } else if (el && el.isContentEditable) {
                        el.focus(); el.innerHTML = ''; el.appendChild(document.createTextNode(String(v)));
                    } else {
                        el.textContent = String(v);
                    }
                    el.dispatchEvent(new Event('input',  { bubbles: true }));
                    el.dispatchEvent(new Event('change', { bubbles: true }));
                }""",
                text
            )
        except Exception:
            raise

def _smartai_find_in(ctx, key: str):
    try:
        css = (
            f"[data-smartai-label*='{key}' i],"
            f"[data-smartai-name*='{key}' i],"
            f"[data-smartai-key*='{key}' i]"
        )
        loc = ctx.locator(css)
        if loc.count() > 0:
            return _visible_first(loc)
    except Exception:
        pass
    return None

def _attr_probe(ctx, key: str):
    # common attributes: name/id/aria-label/data-testid contains key
    try:
        css = (
            f"input[name*='{key}' i], textarea[name*='{key}' i], "
            f"input[id*='{key}' i], textarea[id*='{key}' i], "
            f"[aria-label*='{key}' i], [data-testid*='{key}' i], [data-test*='{key}' i]"
        )
        loc = ctx.locator(css)
        if loc.count() > 0:
            return _visible_first(loc)
    except Exception:
        pass
    return None

def _enter_value(page, label: str, value: str):
    """
    Fill any input/textarea without site-specific selectors. Order:
      0) SmartAI hint
      1) label (strict/contains)
      2) placeholder
      3) role=textbox (covers <textarea>)
      4) proximity to <label>
      5) common attributes (name/id/aria-label/data-testid)
      6) last visible textbox fallback
    Uses medium-speed typing by default (UI_SPEED/UI_TYPING_DELAY).
    """
    import re as _re
    delay, settle = _speed_conf()

    core = (label or "").strip()
    relaxed_rx  = _re.compile(rf"^\s*{_re.escape(core)}\s*:?\s*$", _re.I) if core else None
    contains_rx = _re.compile(_re.escape(core), _re.I) if core else None

    def _fill_here(loc):
        try: loc.scroll_into_view_if_needed()
        except Exception: pass
        _type_fill(loc, value, delay)
        time.sleep(settle/1000.0)

    for ctx in _all_contexts(page):
        if core:
            loc = _smartai_find_in(ctx, core)
            if loc: _fill_here(loc); return

        if relaxed_rx:
            try:
                loc = _visible_first(ctx.get_by_label(relaxed_rx))
                if not loc and contains_rx:
                    loc = _visible_first(ctx.get_by_label(contains_rx))
                if loc: _fill_here(loc); return
            except Exception:
                pass

        if relaxed_rx or contains_rx:
            try:
                loc = _visible_first(ctx.get_by_placeholder(relaxed_rx or contains_rx))
                if not loc and contains_rx and relaxed_rx:
                    loc = _visible_first(ctx.get_by_placeholder(contains_rx))
                if loc: _fill_here(loc); return
            except Exception:
                pass

        if relaxed_rx or contains_rx:
            try:
                loc = _visible_first(ctx.get_by_role("textbox", name=relaxed_rx or contains_rx))
                if not loc and contains_rx and relaxed_rx:
                    loc = _visible_first(ctx.get_by_role("textbox", name=contains_rx))
                if loc: _fill_here(loc); return
            except Exception:
                pass

        if core:
            try:
                prox = ctx.locator(
                    f"label:has-text('{core}') ~ textarea, "
                    f"label:has-text('{core}') ~ input, "
                    f"*:has(> label:has-text('{core}')) textarea, "
                    f"*:has(> label:has-text('{core}')) input, "
                    f"label:has-text('{core}') ~ [contenteditable='true'], "
                    f"*:has(> label:has-text('{core}')) [contenteditable='true']"
                )
                loc = _visible_first(prox.filter("textarea")) or _visible_first(prox)
                if loc: _fill_here(loc); return
            except Exception:
                pass

        if core:
            loc = _attr_probe(ctx, core)
            if loc: _fill_here(loc); return

    try:
        tx = page.get_by_role("textbox")
        if tx.count() > 0:
            _fill_here(tx.nth(tx.count()-1)); return
    except Exception:
        pass

    print(f"[UI-RUNNER] Could not fill value for label '{label}'.")

def _select_dropdown_in_context(ctx, label_text: str, value: str) -> bool:
    import re
    label_rx    = re.compile(label_text, re.I)
    value_exact = re.compile(rf"^{re.escape(value)}$", re.I)
    value_fuzzy = re.compile(value, re.I)

    try:
        sel = ctx.get_by_label(label_rx)
        try: sel.select_option(value=value); return True
        except Exception: pass
        try: sel.select_option(label=value); return True
        except Exception: pass
    except Exception:
        pass

    try:
        near_select = ctx.locator(
            f"label:has-text('{label_text}') ~ select, "
            f"*:has(> label:has-text('{label_text}')) select"
        ).first
        if near_select.count() > 0:
            try: near_select.select_option(value=value); return True
            except Exception: pass
            try: near_select.select_option(label=value); return True
            except Exception: pass
    except Exception:
        pass

    try:
        trigger = ctx.get_by_role("combobox", name=label_rx).first
        if trigger and trigger.count() > 0:
            trigger.click()
            for rx in (value_exact, value_fuzzy):
                try: ctx.get_by_role("option", name=rx).first.click(timeout=2000); return True
                except Exception: pass
            try:
                lb = ctx.get_by_role("listbox").first
                lb.get_by_role("option", name=value_fuzzy).first.click(timeout=2000); return True
            except Exception: pass
    except Exception:
        pass

    try:
        btn = ctx.get_by_role("button", name=label_rx).first
        if btn and btn.count() > 0:
            btn.click()
            for role in ("option", "menuitem"):
                for rx in (value_exact, value_fuzzy):
                    try: ctx.get_by_role(role, name=rx).first.click(timeout=2000); return True
                    except Exception: pass
            for rx in (value_exact, value_fuzzy):
                try: ctx.get_by_text(rx).first.click(timeout=2000); return True
                except Exception: pass
    except Exception:
        pass

    try:
        tb = ctx.get_by_label(label_rx).or_(ctx.get_by_role("textbox", name=label_rx)).first
        if tb.count() == 0:
            tb = ctx.locator(
                f"label:has-text('{label_text}') ~ * [role='textbox'], "
                f"*:has(> label:has-text('{label_text}')) [role='textbox']"
            ).first
        if tb.count() > 0:
            tb.click(); tb.fill(""); tb.type(value)
            try: ctx.get_by_role("option", name=value_fuzzy).first.click(timeout=1200); return True
            except Exception: pass
            try: tb.press("Enter"); return True
            except Exception: pass
    except Exception:
        pass

    try:
        ctx.get_by_text(label_rx).first.click()
        for role in ("option", "menuitem"):
            try: ctx.get_by_role(role, name=value_fuzzy).first.click(timeout=1500); return True
            except Exception: pass
        ctx.get_by_text(value_fuzzy).first.click(timeout=1500); return True
    except Exception:
        pass

    return False

def _select_dropdown(page, label_text: str, value: str) -> bool:
    try:
        if _select_dropdown_in_context(page, label_text, value): return True
    except Exception as e:
        print(f"[UI-RUNNER] select in page failed: {e!r}")

    try:
        for fr in page.frames:
            if fr is page.main_frame: continue
            if _select_dropdown_in_context(fr, label_text, value): return True
    except Exception as e:
        print(f"[UI-RUNNER] select in frames failed: {e!r}")

    print(f"[UI-RUNNER] Could not select '{value}' for '{label_text}'.")
    return False

def _call_or_fallback(fn_name: str, page, *args):
    import re
    g = globals()
    fn = g.get(fn_name)
    if callable(fn): return fn(page, *args)

    try:
        if fn_name.startswith("click_"):
            label = fn_name[len("click_"):].replace("_", " ").strip()
            try: page.get_by_role("button", name=re.compile(label, re.I)).first.click(); return
            except Exception: pass
            try: page.get_by_role("link", name=re.compile(label, re.I)).first.click(); return
            except Exception: pass
            page.get_by_text(re.compile(label, re.I)).first.click(); return

        if fn_name.startswith("enter_"):
            label = fn_name[len("enter_"):].replace("_", " ").strip()
            value = args[0] if args else ""
            return _enter_value(page, label, value)

        if fn_name.startswith("select_"):
            label = fn_name[len("select_"):].replace("_", " ").strip()
            value = args[0] if args else ""
            if _select_dropdown(page, label, value): return
            for alt in (f"{label} Type", f"{label} Name", f"{label} Category", f"Select {label}"):
                if _select_dropdown(page, alt, value): return
            plain = re.sub(r"[\*:\-]+", " ", label).strip()
            if plain != label and _select_dropdown(page, plain, value): return
            return
    except Exception as e:
        print(f"[UI-RUNNER] Fallback failed for {fn_name}: {e!r}")

def _load_form_values():
    """
    No hard-coded values.
    Priority:
      1) FORM_VALUES_PATH JSON
      2) Env vars (UI_*), dynamically mapped to keys
      3) Empty string
    """
    cfg_path = os.getenv("FORM_VALUES_PATH", "")
    data = {}
    if cfg_path:
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                data = json.load(f) or {}
        except Exception as e:
            print(f"[UI-RUNNER] Could not load FORM_VALUES_PATH={cfg_path}: {e!r}")

    # Merge env UI_* (convert UI_FOO -> "foo")
    for k, v in os.environ.items():
        if k.startswith("UI_") and k not in {
            "UI_RUNNER_HEADLESS","UI_RUNNER_SLOWMO","UI_RUNNER_TIMEOUT","UI_RUNNER_NAV_TIMEOUT",
            "UI_RUNNER_HOLD","UI_RUNNER_PAUSE","UI_RUNNER_AUTOCLOSE","UI_TARGET_URL",
            "UI_SPEED","UI_TYPING_DELAY"
        }:
            data.setdefault(k[3:].lower(), v)

    def env(k): return os.getenv(k, "")

    return {
        "name":    data.get("name",    env("UI_NAME")),
        "email":   data.get("email",   env("UI_EMAIL")),
        "phone":   data.get("phone",   env("UI_PHONE")),
        "subject": data.get("subject", env("UI_SUBJECT")),
        "message": data.get("message", env("UI_MESSAGE")),
        "url":     data.get("url",     env("UI_TARGET_URL")),
    }
def run_positive_add_new_customer():
    vals = _load_form_values()
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=(os.getenv("UI_RUNNER_HEADLESS", "false").lower() == "true"),
            slow_mo=int(os.getenv("UI_RUNNER_SLOWMO", "0"))
        )
        context = browser.new_context()
        page = context.new_page()

        # Attach SmartAI metadata if present
        metadata_path = _SRC_ROOT / "metadata" / "after_enrichment.json"
        if metadata_path.exists():
            try:
                patch_page_with_smartai(page, json.loads(metadata_path.read_text(encoding="utf-8")))
            except Exception as e:
                print(f"[UI-RUNNER] SmartAI patch skipped: {e!r}")

        page.set_default_timeout(int(os.getenv("UI_RUNNER_TIMEOUT", "15000")))
        page.set_default_navigation_timeout(int(os.getenv("UI_RUNNER_NAV_TIMEOUT", "30000")))

        # URL comes from FORM_VALUES_PATH/UI_TARGET_URL; if empty, stay on blank
        target_url = vals.get("url")
        if target_url:
            page.goto(target_url)

        page.goto("https://preview--bank-buddy-crm-react.loveable.app/")
        _call_or_fallback("click_customer", page)
        _call_or_fallback("click_new_customer", page)
        _call_or_fallback("enter_full_name", page, "John Doe")
        _call_or_fallback("enter_email", page, "johhn.doe@example.com")
        _call_or_fallback("enter_address", page, "123 Main ST, Anytown, ZUZSA")
        _call_or_fallback("enter_occupation", page, "Software Engineer")
        _call_or_fallback("enter_annual_income", page, "75000")
        _call_or_fallback("enter_initial_deposit", page, "1000")
        _call_or_fallback("click_add_new_customer", page)

        hold_secs = int(os.getenv("UI_RUNNER_HOLD", "8"))
        print(f"[UI-RUNNER] Holding browser open for {hold_secs}s (set UI_RUNNER_HOLD to change)...")
        time.sleep(hold_secs)
        if os.getenv("UI_RUNNER_PAUSE", "0") == "1":
            input("\n[UI-RUNNER] Press Enter to close the browser...")
        if os.getenv("UI_RUNNER_AUTOCLOSE", "1") == "1":
            context.close(); browser.close()


def run_negative_add_new_customer():
    vals = _load_form_values()
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=(os.getenv("UI_RUNNER_HEADLESS", "false").lower() == "true"),
            slow_mo=int(os.getenv("UI_RUNNER_SLOWMO", "0"))
        )
        context = browser.new_context()
        page = context.new_page()

        # Attach SmartAI metadata if present
        metadata_path = _SRC_ROOT / "metadata" / "after_enrichment.json"
        if metadata_path.exists():
            try:
                patch_page_with_smartai(page, json.loads(metadata_path.read_text(encoding="utf-8")))
            except Exception as e:
                print(f"[UI-RUNNER] SmartAI patch skipped: {e!r}")

        page.set_default_timeout(int(os.getenv("UI_RUNNER_TIMEOUT", "15000")))
        page.set_default_navigation_timeout(int(os.getenv("UI_RUNNER_NAV_TIMEOUT", "30000")))

        # URL comes from FORM_VALUES_PATH/UI_TARGET_URL; if empty, stay on blank
        target_url = vals.get("url")
        if target_url:
            page.goto(target_url)

        page.goto("https://preview--bank-buddy-crm-react.loveable.app/")
        _call_or_fallback("click_customer", page)
        _call_or_fallback("click_new_customer", page)
        _call_or_fallback("enter_full_name", page, "John Doe")
        _call_or_fallback("enter_email", page, "johhn.doeexample.com")
        _call_or_fallback("enter_address", page, "123 Main ST, Anytown, ZUZSA")
        _call_or_fallback("enter_occupation", page, "Software Engineer")
        _call_or_fallback("enter_annual_income", page, "75000")
        _call_or_fallback("enter_initial_deposit", page, "1000")
        _call_or_fallback("click_add_new_customer", page)

        hold_secs = int(os.getenv("UI_RUNNER_HOLD", "8"))
        print(f"[UI-RUNNER] Holding browser open for {hold_secs}s (set UI_RUNNER_HOLD to change)...")
        time.sleep(hold_secs)
        if os.getenv("UI_RUNNER_PAUSE", "0") == "1":
            input("\n[UI-RUNNER] Press Enter to close the browser...")
        if os.getenv("UI_RUNNER_AUTOCLOSE", "1") == "1":
            context.close(); browser.close()


def run_edge_add_new_customer():
    vals = _load_form_values()
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=(os.getenv("UI_RUNNER_HEADLESS", "false").lower() == "true"),
            slow_mo=int(os.getenv("UI_RUNNER_SLOWMO", "0"))
        )
        context = browser.new_context()
        page = context.new_page()

        # Attach SmartAI metadata if present
        metadata_path = _SRC_ROOT / "metadata" / "after_enrichment.json"
        if metadata_path.exists():
            try:
                patch_page_with_smartai(page, json.loads(metadata_path.read_text(encoding="utf-8")))
            except Exception as e:
                print(f"[UI-RUNNER] SmartAI patch skipped: {e!r}")

        page.set_default_timeout(int(os.getenv("UI_RUNNER_TIMEOUT", "15000")))
        page.set_default_navigation_timeout(int(os.getenv("UI_RUNNER_NAV_TIMEOUT", "30000")))

        # URL comes from FORM_VALUES_PATH/UI_TARGET_URL; if empty, stay on blank
        target_url = vals.get("url")
        if target_url:
            page.goto(target_url)

        page.goto("https://preview--bank-buddy-crm-react.loveable.app/")
        _call_or_fallback("click_customer", page)
        _call_or_fallback("click_new_customer", page)
        _call_or_fallback("enter_full_name", page, "")
        _call_or_fallback("enter_email", page, "")
        _call_or_fallback("enter_address", page, "")
        _call_or_fallback("enter_occupation", page, "")
        _call_or_fallback("enter_annual_income", page, "")
        _call_or_fallback("enter_initial_deposit", page, "")
        _call_or_fallback("click_add_new_customer", page)

        hold_secs = int(os.getenv("UI_RUNNER_HOLD", "8"))
        print(f"[UI-RUNNER] Holding browser open for {hold_secs}s (set UI_RUNNER_HOLD to change)...")
        time.sleep(hold_secs)
        if os.getenv("UI_RUNNER_PAUSE", "0") == "1":
            input("\n[UI-RUNNER] Press Enter to close the browser...")
        if os.getenv("UI_RUNNER_AUTOCLOSE", "1") == "1":
            context.close(); browser.close()


if __name__ == '__main__':
    run_positive_add_new_customer()
    run_negative_add_new_customer()
    run_edge_add_new_customer()
