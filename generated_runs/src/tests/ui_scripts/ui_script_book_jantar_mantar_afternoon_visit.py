# Auto-generated ui runner
import sys
import os
import re
from pathlib import Path as _Path

_PROJECT_ROOT = _Path("C:\\Users\\rswap\\OneDrive\\Desktop\\project\\testify-automator-ai\\backend\\organizations\\manoj\\127-12") if "C:\\Users\\rswap\\OneDrive\\Desktop\\project\\testify-automator-ai\\backend\\organizations\\manoj\\127-12" else None

# Ensure src is on sys.path
_SCRIPT_PATH = _Path(__file__).resolve()
_ENV_SRC = os.getenv("SMARTAI_SRC_DIR", "").strip()
if _ENV_SRC:
    _SRC_ROOT = _Path(_ENV_SRC).resolve()
else:
    _SRC_ROOT = None
    for _parent in _SCRIPT_PATH.parents:
        if _parent.name == "src":
            _SRC_ROOT = _parent
            break
    if _SRC_ROOT is None:
        _SRC_ROOT = _SCRIPT_PATH.parents[2]

if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))

# Add backend root to sys.path
_ENV_BACKEND = os.getenv("SMARTAI_BACKEND_ROOT", "").strip()
if _ENV_BACKEND:
    _BACKEND_ROOT = _Path(_ENV_BACKEND).resolve()
else:
    _BACKEND_ROOT = None
    for _parent in _SCRIPT_PATH.parents:
        if _parent.name == "backend":
            _BACKEND_ROOT = _parent
            break
    if _BACKEND_ROOT is None:
        _BACKEND_ROOT = _SCRIPT_PATH.parents[7]

if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from playwright.sync_api import sync_playwright, expect
import pytest
import json
import inspect
import functools
from pathlib import Path
from pages.first_page_methods import *
from pages.secnd_page_methods import *
from pages.third_page_methods import *
from lib.smart_ai import patch_page_with_smartai
from lib.ui_actions import safe_drag_and_drop
from lib.allure_runtime import run_allure_case, set_current_page

def _select_timeout_ms():
    try:
        return int(os.getenv("SMARTAI_SELECT_TIMEOUT_MS", "2000"))
    except Exception:
        return 2000

try:
    import allure  # type: ignore
    from allure_commons.types import AttachmentType  # type: ignore
except Exception:  # pragma: no cover
    allure = None
    AttachmentType = None

def _allure_attach_text(name, text):
    if not allure or not AttachmentType:
        return
    try:
        allure.attach(str(text), name=name, attachment_type=AttachmentType.TEXT)
    except Exception:
        pass

def _allure_attach_png(name, data):
    if not allure or not AttachmentType:
        return
    try:
        allure.attach(data, name=name, attachment_type=AttachmentType.PNG)
    except Exception:
        pass

def _attach_failure_context(page):
    try:
        url = page.url
    except Exception:
        url = ""
    if url:
        _allure_attach_text("page_url", url)

    action = getattr(page, "_last_action", None)
    if action:
        _allure_attach_text("last_action", action)

    locator = getattr(page, "_last_locator", None)
    if not locator:
        return

    meta = getattr(locator, "_element_meta", None)
    if meta:
        try:
            _allure_attach_text("last_element_meta", json.dumps(meta, indent=2))
        except Exception:
            pass

    try:
        target = locator.first if hasattr(locator, "first") else locator
    except Exception:
        target = locator

    try:
        outer_html = target.evaluate("el => (el && el.outerHTML) ? el.outerHTML : ''")
        if outer_html:
            _allure_attach_text("last_element_html", outer_html)
    except Exception:
        pass

    try:
        text = target.evaluate("el => (el && el.textContent) ? el.textContent : ''")
        if text:
            _allure_attach_text("last_element_text", text.strip())
    except Exception:
        pass

    try:
        bbox = target.bounding_box()
        if bbox:
            _allure_attach_text("last_element_bbox", json.dumps(bbox))
    except Exception:
        pass

def _safe_screenshot(page, name="failure"):
    try:
        _attach_failure_context(page)
        manager = getattr(page, "_visual_manager", None)
        if manager:
            manager.start_test(os.getenv("SMARTAI_VISUAL_TEST_NAME", "") or "unknown_test")
            manager.on_failure(label=name)
        try:
            locator = getattr(page, "_last_locator", None)
            if locator:
                target = locator.first if hasattr(locator, "first") else locator
                try:
                    target.scroll_into_view_if_needed(timeout=1000)
                except Exception:
                    pass
                try:
                    target.evaluate(
                        "el => { if (!el) return; el.setAttribute('data-smartai-highlight','1');"
                        "el.style.outline='3px solid #ff3b30'; el.style.outlineOffset='2px';"
                        "el.style.boxShadow='0 0 0 2px rgba(255,59,48,0.4)'; }"
                    )
                except Exception:
                    pass
        except Exception:
            pass
        data = page.screenshot(full_page=False)
    except Exception:
        return
    _allure_attach_png(name, data)

def _write_allure_environment():
    results_dir = os.getenv("ALLURE_RESULTS_DIR", "allure-results")
    try:
        project_dir = ""
        try:
            if _PROJECT_ROOT:
                project_dir = str(_PROJECT_ROOT)
        except Exception:
            project_dir = ""
        os.makedirs(results_dir, exist_ok=True)
        env_path = _Path(results_dir) / "environment.properties"
        lines = [
            "base_url=" + os.getenv("SITE_URL", ""),
            "project_id=" + os.getenv("SMARTAI_PROJECT_ID", ""),
            "project_dir=" + project_dir,
            "browser=chromium",
        ]
        env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except Exception:
        pass

def _attach_page_helpers(target_page):
    for name, helper in globals().items():
        if not inspect.isfunction(helper):
            continue
        module = getattr(helper, "__module__", "")
        if not module.startswith("pages."):
            continue
        if name.startswith("_"):
            continue
        if hasattr(target_page, name):
            continue
        setattr(target_page, name, functools.partial(helper, target_page))

def _dismiss_cookie_banner(page):
    selectors = [
        "text=/^Accept all$/i",
        "text=/^Accept$/i",
        "text=/^I agree$/i",
        "text=/^Agree$/i",
        "text=/^Close$/i",
        "text=/^Not now$/i",
        "text=/^Skip$/i",
        "text=/^No thanks$/i",
        "button:has-text('Accept all')",
        "button:has-text('Accept')",
        "button:has-text('I agree')",
        "button:has-text('Close')",
        "button:has-text('Not now')",
        "button:has-text('Skip')",
        "button:has-text('No thanks')",
        "button:has-text('×')",
        "button[aria-label*='close' i]",
        "[aria-label*='accept' i]",
        "[aria-label='close']",
        "[aria-label*='close' i]",
        "[class*='modal' i] [class*='close' i]",
        "[class*='login' i] [class*='close' i]",
        "span:has-text('×')",
        "svg[aria-label*='close' i]",
        "[id*='cookie' i] button",
        "[class*='cookie' i] button",
        "[data-testid*='cookie' i] button",
    ]
    for selector in selectors:
        try:
            locator = page.locator(selector).first
            if locator.is_visible(timeout=1000):
                locator.click(timeout=1000)
                return True
        except Exception:
            continue
    return False

def _find_frame_for_field(page, label=None, placeholder=None):
    for fr in page.frames:
        try:
            if label:
                loc = fr.get_by_label(label)
                if loc.count() > 0:
                    return fr
        except Exception:
            pass
        try:
            if placeholder:
                loc = fr.get_by_placeholder(placeholder)
                if loc.count() > 0:
                    return fr
        except Exception:
            pass
    return None

def _smart_fill(page, label, value, placeholder=None):
    def _placeholder_variants(lbl, ph):
        variants = []
        if ph:
            variants.append(ph)
        if lbl:
            variants.append(lbl)
            variants.append(f"Enter {lbl}")
            variants.append(f"Enter {lbl.lower()}")
            variants.append(f"Enter {lbl.title()}")
            parts = [p for p in re.split(r"\s+", lbl) if p]
            if parts:
                last = parts[-1]
                variants.append(f"Enter {last}")
                variants.append(f"Enter {last.lower()}")
                variants.append(f"Enter {last.title()}")
        # dedupe preserving order
        seen = set()
        out = []
        for v in variants:
            if v and v not in seen:
                seen.add(v)
                out.append(v)
        return out

    # Try label-based lookup inside frames first
    target = _find_frame_for_field(page, label=label) or page
    try:
        target.get_by_label(label).fill(value)
        return
    except Exception:
        pass

    # Try placeholder variants inside frames
    for ph in _placeholder_variants(label, placeholder):
        target = _find_frame_for_field(page, placeholder=ph) or page
        try:
            target.get_by_placeholder(ph).fill(value)
            return
        except Exception:
            continue

    # Last resort: main page label
    page.get_by_label(label).fill(value)

def fill_text(page, field_label, value):
    return _smart_fill(page, field_label, value)

def _xpath_literal(text):
    if "'" not in text:
        return "'" + text + "'"
    if '"' not in text:
        return '"' + text + '"'
    parts = text.split("'")
    items = []
    for index, part in enumerate(parts):
        items.append("'" + part + "'")
        if index != len(parts) - 1:
            items.append('"\'"')
    return "concat(" + ", ".join(items) + ")"

def _get_checkbox_locator(page, label):
    exact_re = re.compile(r"^\s*" + re.escape(label) + r"\s*$", re.I)
    exact_label = _xpath_literal(label)
    try:
        loc = page.get_by_label(label, exact=True)
        if loc.count() > 0:
            return loc.first
    except Exception:
        pass
    try:
        loc = page.get_by_label(re.compile(r"^" + re.escape(label) + r"$", re.I))
        if loc.count() > 0:
            return loc.first
    except Exception:
        pass
    try:
        loc = page.get_by_role("checkbox", name=label, exact=True)
        if loc.count() > 0:
            return loc.first
    except Exception:
        pass
    try:
        loc = page.get_by_role("checkbox", name=re.compile(r"^" + re.escape(label) + r"$", re.I))
        if loc.count() > 0:
            return loc.first
    except Exception:
        pass
    try:
        loc = page.locator("label").filter(has_text=exact_re).locator(
            "input[type='checkbox'], input[type='radio'], [role='checkbox'], [role='radio']"
        )
        if loc.count() > 0:
            return loc.first
    except Exception:
        pass
    try:
        xpath = (
            "//label[normalize-space(.)=" + exact_label + "]"
            "//input[@type='checkbox' or @type='radio']"
            " | //label[normalize-space(.)=" + exact_label + "]/preceding-sibling::input[@type='checkbox' or @type='radio'][1]"
            " | //label[normalize-space(.)=" + exact_label + "]/following-sibling::input[@type='checkbox' or @type='radio'][1]"
        )
        loc = page.locator("xpath=" + xpath)
        if loc.count() > 0:
            return loc.first
    except Exception:
        pass
    try:
        xpath = (
            "//*[self::div or self::li or self::td or self::tr or self::span]"
            "[normalize-space(.)=" + exact_label + "]"
            "/ancestor-or-self::*[self::div or self::li or self::td or self::tr][1]"
            "//*[self::input[@type='checkbox' or @type='radio'] or @role='checkbox' or @role='radio']"
        )
        loc = page.locator("xpath=" + xpath)
        if loc.count() > 0:
            return loc.first
    except Exception:
        pass
    return None

def check_checkbox(page, label):
    locator = _get_checkbox_locator(page, label)
    if not locator:
        raise RuntimeError("Checkbox not found for label: " + str(label))
    try:
        locator.scroll_into_view_if_needed(timeout=1000)
    except Exception:
        pass
    try:
        locator.check()
        return
    except Exception:
        pass
    locator.click()

def select_dropdown(page, field_label, value):
    timeout_ms = _select_timeout_ms()
    locator = None
    try:
        locator = page.get_by_label(field_label, exact=True)
    except Exception:
        locator = None
    if not locator or locator.count() == 0:
        try:
            locator = page.get_by_label(re.compile(r"^" + re.escape(field_label) + r"$", re.I))
        except Exception:
            locator = None
    if not locator or locator.count() == 0:
        try:
            locator = page.get_by_role("combobox", name=field_label, exact=True)
        except Exception:
            locator = None
    if not locator or locator.count() == 0:
        try:
            locator = page.get_by_role("combobox", name=re.compile(r"^" + re.escape(field_label) + r"$", re.I))
        except Exception:
            locator = None
    if not locator or locator.count() == 0:
        try:
            locator = page.locator(
                "xpath=//*[normalize-space(.)='" + field_label + "']/following::*[self::select or @role='combobox'][1]"
            )
        except Exception:
            locator = None
    if not locator or locator.count() == 0:
        try:
            locator = page.locator(
                "xpath=//*[contains(translate(normalize-space(.),'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),"                "'" + field_label.lower() + "')]/following::*[self::select or @role='combobox'][1]"
            )
        except Exception:
            locator = None
    if not locator or locator.count() == 0:
        raise RuntimeError("Dropdown not found for label: " + str(field_label))

    target = locator.first
    try:
        target.scroll_into_view_if_needed(timeout=min(1000, timeout_ms))
    except Exception:
        pass
    try:
        tag = target.evaluate("el => el && el.tagName ? el.tagName.toLowerCase() : ''")
    except Exception:
        tag = ""
    if tag == "select":
        try:
            target.select_option(label=value, timeout=timeout_ms)
            return
        except Exception:
            pass
    try:
        target.click(timeout=timeout_ms)
    except Exception:
        pass
    try:
        opt = page.get_by_role("option", name=value, exact=True)
        if opt.count() > 0:
            opt.first.click(timeout=timeout_ms)
            return
    except Exception:
        pass
    try:
        opt = page.get_by_role("option", name=re.compile(r"^" + re.escape(value) + r"$", re.I))
        if opt.count() > 0:
            opt.first.click(timeout=timeout_ms)
            return
    except Exception:
        pass
    try:
        page.get_by_text(value, exact=True).click(timeout=timeout_ms)
        return
    except Exception:
        pass
    raise RuntimeError("Option not found: " + str(value) + " for dropdown " + str(field_label))

def click_button(page, label):
    try:
        loc = page.get_by_role("button", name=label, exact=True)
        if loc.count() > 0:
            loc.first.click()
            return
    except Exception:
        pass
    try:
        loc = page.get_by_role("button", name=re.compile(r"^" + re.escape(label) + r"$", re.I))
        if loc.count() > 0:
            loc.first.click()
            return
    except Exception:
        pass
    try:
        page.get_by_text(label, exact=True).click()
        return
    except Exception:
        pass
    try:
        loc = page.get_by_role("link", name=re.compile(re.escape(label), re.I))
        if loc.count() > 0:
            loc.first.click()
            return
    except Exception:
        pass
    try:
        page.get_by_text(re.compile(re.escape(label), re.I)).first.click()
        return
    except Exception:
        pass
    raise RuntimeError("Button not found: " + str(label))

RUN_TAGS = {
    "TS_001_TC_001_book_jantar_mantar_afternoon_visit_positive": [
        "regression"
    ],
    "TS_001_TC_002_book_jantar_mantar_afternoon_visit_negative": [
        "functional"
    ],
    "TS_001_TC_003_book_jantar_mantar_afternoon_visit_edge": [
        "functional"
    ]
}

@pytest.mark.regression
def TS_001_TC_001_book_jantar_mantar_afternoon_visit_positive():
    import time
    import os
    from pathlib import Path as _Path
    with sync_playwright() as p:
        _write_allure_environment()
        browser = p.chromium.launch(headless=False, slow_mo=300)

        # Attempt to restore cookies / localStorage from a Playwright storage_state file.
        # Priority: auth/storage.json
        storage_file = None
        restored_storage = False
        project_root = ""
        try:
            if _PROJECT_ROOT:
                project_root = str(_PROJECT_ROOT)
        except Exception:
            project_root = ""
        if not project_root:
            for parent in _Path(__file__).resolve().parents:
                if parent.name == "generated_runs":
                    project_root = str(parent.parent)
                    break
        if project_root:
            candidate = _Path(project_root) / "auth" / "storage.json"
            if candidate.exists():
                storage_file = candidate

        if storage_file and storage_file.exists():
            try:
                context = browser.new_context(storage_state=str(storage_file))
                page = context.new_page()
                print(f"[ui_runner] Restored storage_state from: {storage_file}")
                restored_storage = True
            except Exception as e:
                print(f"[ui_runner] Failed to restore storage_state: {e}")
                context = browser.new_context()
                page = context.new_page()
        else:
            expected = ""
            if project_root:
                expected = str(_Path(project_root) / "auth" / "storage.json")
            print(f"[ui_runner] No storage_state file found. Expected: {expected}")
            context = browser.new_context()
            page = context.new_page()
        set_current_page(page)
        _attach_page_helpers(page)
        # Patch SmartAI
        metadata_path = _SRC_ROOT / "metadata" / "after_enrichment.json"
        with open(metadata_path, "r") as f:
            actual_metadata = json.load(f)
        _allure_attach_text("story", "Given I am on the https://asi.paygov.org.in/\nAnd I verify \"ARCHAEOLOGICAL SURVEY OF INDIA\" is visible ,                                                                                                                                And I check \"Delhi\" checkbox,\nAnd I check \"Jantar Mantar\" checkbox,\nAnd I select \"Afternoon\" in \"Visit time\" field,\nAnd I click on \"Proceed\" button,                                                                                                                                                                                                                                        And I verify \"Note: Adult age above 15 yrs & child age below 15 yrs\nAnd I enter \"abcd\" in \"Name\" field,\nAnd I enter \"33\" in \"Age\" field,\nAnd I enter \"asfb@gmail.com\" in \"Email\" field,\nAnd I enter \"7897852147\" in \"Mobile No\" field,\nAnd I click on \"Proceed to pay\" button\nAnd I enter \"473424243342\" in \"Card Number\" field,\nAnd I select \"12\" for \"Expiry Month\",\nAnd I select \"2033\" for \"Expiry Year\"\nAnd I enter \"Abcd\" in \"Name on Card\" field,\nAnd I enter \"123\" in \"CVV\" field,\nAnd I click \"Pay Now\" button")
        try:
            page.goto("https://asi.paygov.org.in/")
            page.wait_for_load_state("domcontentloaded")
            _dismiss_cookie_banner(page)
            auth_landing = os.getenv("SMARTAI_AUTH_LANDING_URL", "").strip()
            if not auth_landing:
                project_root = ""
                try:
                        if _PROJECT_ROOT:
                            project_root = str(_PROJECT_ROOT)
                except Exception:
                        project_root = ""
                if not project_root:
                        for parent in _Path(__file__).resolve().parents:
                            if parent.name == "generated_runs":
                                    project_root = str(parent.parent)
                                    break
                if project_root:
                        landing_file = _Path(project_root) / "auth" / "landing_url.txt"
                        try:
                            if landing_file.exists():
                                    auth_landing = landing_file.read_text(encoding="utf-8").strip()
                        except Exception:
                            auth_landing = ""
            try:
                current_url = page.url or ""
            except Exception:
                current_url = ""
            if auth_landing:
                page.goto(auth_landing)
                page.wait_for_load_state("domcontentloaded")
                _dismiss_cookie_banner(page)
                try:
                        current_url = page.url or ""
                except Exception:
                        current_url = ""
            if restored_storage and current_url and any(k in current_url.lower() for k in ("login", "signin", "sign-in", "auth")):
                raise RuntimeError(
                        "Session not authenticated (still on login page). "
                        "Refresh auth storage and re-run."
                )
            patch_page_with_smartai(page, actual_metadata)
            expect(page.get_by_text("ARCHAEOLOGICAL SURVEY OF INDIA", exact=True).first).to_be_visible()
            check_delhi(page)
            check_checkbox(page, "Jantar Mantar")
            select_dropdown(page, "Visit time", "Afternoon")
            click_proceed_to_pay(page)
            expect(page.get_by_text("Note: Adult age above 15 yrs & child age below 15 yrs", exact=True).first).to_be_visible()
            enter_name(page, "abcd")
            enter_age(page, "33")
            enter_email(page, "asfb@gmail.com")
            enter_mobile_no(page, "7897852147")
            click_proceed_to_pay(page)
            enter_card_number(page, "473424243342")
            select_expiry_month_mm(page, "12")
            select_expiry_year_yyyy(page, "2033")
            enter_name_on_card(page, "Abcd")
            enter_cvv(page, "123")
            click_pay_now(page)

        except Exception:
            _safe_screenshot(page, "failure")
            raise
        try:
            pause_s = float(os.getenv("SMARTAI_POST_RUN_PAUSE_SEC", "1"))
        except Exception:
            pause_s = 1
        if pause_s > 0:
            time.sleep(pause_s)
        try:
            context.close()
        except Exception:
            pass
        browser.close()

@pytest.mark.functional
def TS_001_TC_002_book_jantar_mantar_afternoon_visit_negative():
    import time
    import os
    from pathlib import Path as _Path
    with sync_playwright() as p:
        _write_allure_environment()
        browser = p.chromium.launch(headless=False, slow_mo=300)

        # Attempt to restore cookies / localStorage from a Playwright storage_state file.
        # Priority: auth/storage.json
        storage_file = None
        restored_storage = False
        project_root = ""
        try:
            if _PROJECT_ROOT:
                project_root = str(_PROJECT_ROOT)
        except Exception:
            project_root = ""
        if not project_root:
            for parent in _Path(__file__).resolve().parents:
                if parent.name == "generated_runs":
                    project_root = str(parent.parent)
                    break
        if project_root:
            candidate = _Path(project_root) / "auth" / "storage.json"
            if candidate.exists():
                storage_file = candidate

        if storage_file and storage_file.exists():
            try:
                context = browser.new_context(storage_state=str(storage_file))
                page = context.new_page()
                print(f"[ui_runner] Restored storage_state from: {storage_file}")
                restored_storage = True
            except Exception as e:
                print(f"[ui_runner] Failed to restore storage_state: {e}")
                context = browser.new_context()
                page = context.new_page()
        else:
            expected = ""
            if project_root:
                expected = str(_Path(project_root) / "auth" / "storage.json")
            print(f"[ui_runner] No storage_state file found. Expected: {expected}")
            context = browser.new_context()
            page = context.new_page()
        set_current_page(page)
        _attach_page_helpers(page)
        # Patch SmartAI
        metadata_path = _SRC_ROOT / "metadata" / "after_enrichment.json"
        with open(metadata_path, "r") as f:
            actual_metadata = json.load(f)
        _allure_attach_text("story", "Given I am on the https://asi.paygov.org.in/\nAnd I verify \"ARCHAEOLOGICAL SURVEY OF INDIA\" is visible ,                                                                                                                                And I check \"Delhi\" checkbox,\nAnd I check \"Jantar Mantar\" checkbox,\nAnd I select \"Afternoon\" in \"Visit time\" field,\nAnd I click on \"Proceed\" button,                                                                                                                                                                                                                                        And I verify \"Note: Adult age above 15 yrs & child age below 15 yrs\nAnd I enter \"abcd\" in \"Name\" field,\nAnd I enter \"33\" in \"Age\" field,\nAnd I enter \"asfb@gmail.com\" in \"Email\" field,\nAnd I enter \"7897852147\" in \"Mobile No\" field,\nAnd I click on \"Proceed to pay\" button\nAnd I enter \"473424243342\" in \"Card Number\" field,\nAnd I select \"12\" for \"Expiry Month\",\nAnd I select \"2033\" for \"Expiry Year\"\nAnd I enter \"Abcd\" in \"Name on Card\" field,\nAnd I enter \"123\" in \"CVV\" field,\nAnd I click \"Pay Now\" button")
        try:
            page.goto("https://asi.paygov.org.in/")
            page.wait_for_load_state("domcontentloaded")
            _dismiss_cookie_banner(page)
            auth_landing = os.getenv("SMARTAI_AUTH_LANDING_URL", "").strip()
            if not auth_landing:
                project_root = ""
                try:
                        if _PROJECT_ROOT:
                            project_root = str(_PROJECT_ROOT)
                except Exception:
                        project_root = ""
                if not project_root:
                        for parent in _Path(__file__).resolve().parents:
                            if parent.name == "generated_runs":
                                    project_root = str(parent.parent)
                                    break
                if project_root:
                        landing_file = _Path(project_root) / "auth" / "landing_url.txt"
                        try:
                            if landing_file.exists():
                                    auth_landing = landing_file.read_text(encoding="utf-8").strip()
                        except Exception:
                            auth_landing = ""
            try:
                current_url = page.url or ""
            except Exception:
                current_url = ""
            if auth_landing:
                page.goto(auth_landing)
                page.wait_for_load_state("domcontentloaded")
                _dismiss_cookie_banner(page)
                try:
                        current_url = page.url or ""
                except Exception:
                        current_url = ""
            if restored_storage and current_url and any(k in current_url.lower() for k in ("login", "signin", "sign-in", "auth")):
                raise RuntimeError(
                        "Session not authenticated (still on login page). "
                        "Refresh auth storage and re-run."
                )
            patch_page_with_smartai(page, actual_metadata)
            expect(page.get_by_text("ARCHAEOLOGICAL SURVEY OF INDIA", exact=True).first).to_be_visible()
            check_delhi(page)
            check_checkbox(page, "Jantar Mantar")
            select_dropdown(page, "Visit time", "Afternoon")
            click_proceed_to_pay(page)
            expect(page.get_by_text("Note: Adult age above 15 yrs & child age below 15 yrs", exact=True).first).to_be_visible()
            enter_name(page, "!")  # Invalid name
            enter_age(page, "33")
            enter_email(page, "asfb@gmail.com")
            enter_mobile_no(page, "7897852147")
            click_proceed_to_pay(page)
            expect(page.get_by_text("Please enter a valid name", exact=True).first).to_be_visible()

        except Exception:
            _safe_screenshot(page, "failure")
            raise
        try:
            pause_s = float(os.getenv("SMARTAI_POST_RUN_PAUSE_SEC", "1"))
        except Exception:
            pause_s = 1
        if pause_s > 0:
            time.sleep(pause_s)
        try:
            context.close()
        except Exception:
            pass
        browser.close()

@pytest.mark.functional
def TS_001_TC_003_book_jantar_mantar_afternoon_visit_edge():
    import time
    import os
    from pathlib import Path as _Path
    with sync_playwright() as p:
        _write_allure_environment()
        browser = p.chromium.launch(headless=False, slow_mo=300)

        # Attempt to restore cookies / localStorage from a Playwright storage_state file.
        # Priority: auth/storage.json
        storage_file = None
        restored_storage = False
        project_root = ""
        try:
            if _PROJECT_ROOT:
                project_root = str(_PROJECT_ROOT)
        except Exception:
            project_root = ""
        if not project_root:
            for parent in _Path(__file__).resolve().parents:
                if parent.name == "generated_runs":
                    project_root = str(parent.parent)
                    break
        if project_root:
            candidate = _Path(project_root) / "auth" / "storage.json"
            if candidate.exists():
                storage_file = candidate

        if storage_file and storage_file.exists():
            try:
                context = browser.new_context(storage_state=str(storage_file))
                page = context.new_page()
                print(f"[ui_runner] Restored storage_state from: {storage_file}")
                restored_storage = True
            except Exception as e:
                print(f"[ui_runner] Failed to restore storage_state: {e}")
                context = browser.new_context()
                page = context.new_page()
        else:
            expected = ""
            if project_root:
                expected = str(_Path(project_root) / "auth" / "storage.json")
            print(f"[ui_runner] No storage_state file found. Expected: {expected}")
            context = browser.new_context()
            page = context.new_page()
        set_current_page(page)
        _attach_page_helpers(page)
        # Patch SmartAI
        metadata_path = _SRC_ROOT / "metadata" / "after_enrichment.json"
        with open(metadata_path, "r") as f:
            actual_metadata = json.load(f)
        _allure_attach_text("story", "Given I am on the https://asi.paygov.org.in/\nAnd I verify \"ARCHAEOLOGICAL SURVEY OF INDIA\" is visible ,                                                                                                                                And I check \"Delhi\" checkbox,\nAnd I check \"Jantar Mantar\" checkbox,\nAnd I select \"Afternoon\" in \"Visit time\" field,\nAnd I click on \"Proceed\" button,                                                                                                                                                                                                                                        And I verify \"Note: Adult age above 15 yrs & child age below 15 yrs\nAnd I enter \"abcd\" in \"Name\" field,\nAnd I enter \"33\" in \"Age\" field,\nAnd I enter \"asfb@gmail.com\" in \"Email\" field,\nAnd I enter \"7897852147\" in \"Mobile No\" field,\nAnd I click on \"Proceed to pay\" button\nAnd I enter \"473424243342\" in \"Card Number\" field,\nAnd I select \"12\" for \"Expiry Month\",\nAnd I select \"2033\" for \"Expiry Year\"\nAnd I enter \"Abcd\" in \"Name on Card\" field,\nAnd I enter \"123\" in \"CVV\" field,\nAnd I click \"Pay Now\" button")
        try:
            page.goto("https://asi.paygov.org.in/")
            page.wait_for_load_state("domcontentloaded")
            _dismiss_cookie_banner(page)
            auth_landing = os.getenv("SMARTAI_AUTH_LANDING_URL", "").strip()
            if not auth_landing:
                project_root = ""
                try:
                        if _PROJECT_ROOT:
                            project_root = str(_PROJECT_ROOT)
                except Exception:
                        project_root = ""
                if not project_root:
                        for parent in _Path(__file__).resolve().parents:
                            if parent.name == "generated_runs":
                                    project_root = str(parent.parent)
                                    break
                if project_root:
                        landing_file = _Path(project_root) / "auth" / "landing_url.txt"
                        try:
                            if landing_file.exists():
                                    auth_landing = landing_file.read_text(encoding="utf-8").strip()
                        except Exception:
                            auth_landing = ""
            try:
                current_url = page.url or ""
            except Exception:
                current_url = ""
            if auth_landing:
                page.goto(auth_landing)
                page.wait_for_load_state("domcontentloaded")
                _dismiss_cookie_banner(page)
                try:
                        current_url = page.url or ""
                except Exception:
                        current_url = ""
            if restored_storage and current_url and any(k in current_url.lower() for k in ("login", "signin", "sign-in", "auth")):
                raise RuntimeError(
                        "Session not authenticated (still on login page). "
                        "Refresh auth storage and re-run."
                )
            patch_page_with_smartai(page, actual_metadata)
            expect(page.get_by_text("ARCHAEOLOGICAL SURVEY OF INDIA", exact=True).first).to_be_visible()
            check_delhi(page)
            check_checkbox(page, "Jantar Mantar")
            select_dropdown(page, "Visit time", "Afternoon")
            click_proceed_to_pay(page)
            expect(page.get_by_text("Note: Adult age above 15 yrs & child age below 15 yrs", exact=True).first).to_be_visible()
            enter_name(page, "a" * 255)  # Edge case: long name
            enter_age(page, "15")  # Edge case: boundary age
            enter_email(page, "asfb@gmail.com")
            enter_mobile_no(page, "7897852147")
            click_proceed_to_pay(page)
            enter_card_number(page, "473424243342")
            select_expiry_month_mm(page, "12")
            select_expiry_year_yyyy(page, "2033")
            enter_name_on_card(page, "Abcd")
            enter_cvv(page, "123")
            click_pay_now(page)

        except Exception:
            _safe_screenshot(page, "failure")
            raise
        try:
            pause_s = float(os.getenv("SMARTAI_POST_RUN_PAUSE_SEC", "1"))
        except Exception:
            pause_s = 1
        if pause_s > 0:
            time.sleep(pause_s)
        try:
            context.close()
        except Exception:
            pass
        browser.close()


if __name__ == '__main__':
    import sys
    import os
    selected_tags = {t.strip().lower() for t in os.getenv('SMARTAI_RUN_TAGS', '').split(',') if t.strip()}
    selected_names = {n.strip() for n in os.getenv('SMARTAI_RUN_FUNCTIONS', '').split(',') if n.strip()}
    def _should_run(name):
        if selected_names:
            return name in selected_names
        if not selected_tags:
            return True
        return any(tag in selected_tags for tag in RUN_TAGS.get(name, []))
    failures = 0
    if _should_run('TS_001_TC_001_book_jantar_mantar_afternoon_visit_positive'):
        try:
            print(f'\n[ui_runner] Running test: TS_001_TC_001_book_jantar_mantar_afternoon_visit_positive...\n')
            run_allure_case('TS_001_TC_001_book_jantar_mantar_afternoon_visit_positive', TS_001_TC_001_book_jantar_mantar_afternoon_visit_positive)
            print(f'\n[ui_runner] TS_001_TC_001_book_jantar_mantar_afternoon_visit_positive: PASS\n')
        except Exception as exc:
            failures += 1
            print(f'\n[ui_runner] TS_001_TC_001_book_jantar_mantar_afternoon_visit_positive: FAIL\nDetails: {exc}\n')
    else:
        print(f'\n[ui_runner] Skipping TS_001_TC_001_book_jantar_mantar_afternoon_visit_positive (tag filter)\n')
    if _should_run('TS_001_TC_002_book_jantar_mantar_afternoon_visit_negative'):
        try:
            print(f'\n[ui_runner] Running test: TS_001_TC_002_book_jantar_mantar_afternoon_visit_negative...\n')
            run_allure_case('TS_001_TC_002_book_jantar_mantar_afternoon_visit_negative', TS_001_TC_002_book_jantar_mantar_afternoon_visit_negative)
            print(f'\n[ui_runner] TS_001_TC_002_book_jantar_mantar_afternoon_visit_negative: PASS\n')
        except Exception as exc:
            failures += 1
            print(f'\n[ui_runner] TS_001_TC_002_book_jantar_mantar_afternoon_visit_negative: FAIL\nDetails: {exc}\n')
    else:
        print(f'\n[ui_runner] Skipping TS_001_TC_002_book_jantar_mantar_afternoon_visit_negative (tag filter)\n')
    if _should_run('TS_001_TC_003_book_jantar_mantar_afternoon_visit_edge'):
        try:
            print(f'\n[ui_runner] Running test: TS_001_TC_003_book_jantar_mantar_afternoon_visit_edge...\n')
            run_allure_case('TS_001_TC_003_book_jantar_mantar_afternoon_visit_edge', TS_001_TC_003_book_jantar_mantar_afternoon_visit_edge)
            print(f'\n[ui_runner] TS_001_TC_003_book_jantar_mantar_afternoon_visit_edge: PASS\n')
        except Exception as exc:
            failures += 1
            print(f'\n[ui_runner] TS_001_TC_003_book_jantar_mantar_afternoon_visit_edge: FAIL\nDetails: {exc}\n')
    else:
        print(f'\n[ui_runner] Skipping TS_001_TC_003_book_jantar_mantar_afternoon_visit_edge (tag filter)\n')

    if failures > 0:
        print(f'\n[ui_runner] Summary: {failures} test(s) failed.')
        sys.exit(1)
    else:
        print(f'\n[ui_runner] Summary: All tests passed.')
        sys.exit(0)
