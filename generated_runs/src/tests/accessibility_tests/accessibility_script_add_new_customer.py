# Auto-generated accessibility runner
import sys
import os
from pathlib import Path as _Path

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

from playwright.sync_api import sync_playwright
import pytest
import json
import inspect
import functools
from pathlib import Path
from pages.bank_add_customer_page_methods import *
from pages.bank_customer_page_methods import *
from pages.bank_dashboard_page_methods import *
from services.accessibility_test_utils import run_accessibility_scan
from lib.smart_ai import patch_page_with_smartai

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

RUN_TAGS = {
    "TS_003_TC_001_add_new_customer_a11y_non_text_content": [
        "regression"
    ],
    "TS_003_TC_002_add_new_customer_a11y_info_and_relationships": [
        "regression"
    ],
    "TS_003_TC_003_add_new_customer_a11y_identify_input_purpose": [
        "regression"
    ],
    "TS_003_TC_004_add_new_customer_a11y_keyboard_access": [
        "regression"
    ],
    "TS_003_TC_005_add_new_customer_a11y_no_keyboard_trap": [
        "regression"
    ],
    "TS_003_TC_006_add_new_customer_a11y_page_title": [
        "regression"
    ],
    "TS_003_TC_007_add_new_customer_a11y_language_of_page": [
        "regression"
    ]
}

@pytest.mark.regression
# AI-analyzed tags: regression | Priority: Low
def TS_003_TC_001_add_new_customer_a11y_non_text_content():
    import time
    import os
    from pathlib import Path as _Path
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False, slow_mo=300)

        # Attempt to restore cookies / localStorage from a Playwright storage_state file.
        # Priority: UI_STORAGE_FILE env -> backend/storage/cookies.json
        storage_file = None
        env_sf = os.getenv("UI_STORAGE_FILE", "").strip()
        if env_sf:
            storage_file = _Path(env_sf)
        else:
            backend_root = os.getenv("SMARTAI_BACKEND_ROOT", "").strip()
            guessed = None
            if backend_root:
                guessed = _Path(backend_root) / "storage" / "cookies.json"
            else:
                for parent in _Path(__file__).resolve().parents:
                    if parent.name == "backend":
                        guessed = parent / "storage" / "cookies.json"
                        break
            if guessed and guessed.exists():
                storage_file = guessed

        if storage_file and storage_file.exists():
            try:
                context = browser.new_context(storage_state=str(storage_file))
                page = context.new_page()
                print(f"[accessibility_runner] Restored storage_state from: {storage_file}")
            except Exception as e:
                print(f"[accessibility_runner] Failed to restore storage_state: {e}")
                context = browser.new_context()
                page = context.new_page()
        else:
            context = browser.new_context()
            page = context.new_page()

        _attach_page_helpers(page)
        # Patch SmartAI
        metadata_path = _SRC_ROOT / "metadata" / "after_enrichment.json"
        with open(metadata_path, "r") as f:
            actual_metadata = json.load(f)
        patch_page_with_smartai(page, actual_metadata)
        page.goto("https://bank-buddy-crm-react.lovable.app/")
        verify_bank_crm_visible(page)
        click_customers(page)
        click_add_new_customer(page)
        expect(page.locator("img:not([alt])")._locator).to_have_count(0)
        # AI-analyzed tags: regression | Priority: Low
        run_accessibility_scan(page)
        time.sleep(3)
        browser.close()

@pytest.mark.regression
# AI-analyzed tags: regression | Priority: Low
def TS_003_TC_002_add_new_customer_a11y_info_and_relationships():
    import time
    import os
    from pathlib import Path as _Path
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False, slow_mo=300)

        # Attempt to restore cookies / localStorage from a Playwright storage_state file.
        # Priority: UI_STORAGE_FILE env -> backend/storage/cookies.json
        storage_file = None
        env_sf = os.getenv("UI_STORAGE_FILE", "").strip()
        if env_sf:
            storage_file = _Path(env_sf)
        else:
            backend_root = os.getenv("SMARTAI_BACKEND_ROOT", "").strip()
            guessed = None
            if backend_root:
                guessed = _Path(backend_root) / "storage" / "cookies.json"
            else:
                for parent in _Path(__file__).resolve().parents:
                    if parent.name == "backend":
                        guessed = parent / "storage" / "cookies.json"
                        break
            if guessed and guessed.exists():
                storage_file = guessed

        if storage_file and storage_file.exists():
            try:
                context = browser.new_context(storage_state=str(storage_file))
                page = context.new_page()
                print(f"[accessibility_runner] Restored storage_state from: {storage_file}")
            except Exception as e:
                print(f"[accessibility_runner] Failed to restore storage_state: {e}")
                context = browser.new_context()
                page = context.new_page()
        else:
            context = browser.new_context()
            page = context.new_page()

        _attach_page_helpers(page)
        # Patch SmartAI
        metadata_path = _SRC_ROOT / "metadata" / "after_enrichment.json"
        with open(metadata_path, "r") as f:
            actual_metadata = json.load(f)
        patch_page_with_smartai(page, actual_metadata)
        page.goto("https://bank-buddy-crm-react.lovable.app/")
        verify_bank_crm_visible(page)
        click_customers(page)
        click_add_new_customer(page)
        inputs = page.locator("input")
        unlabeled_count = inputs.evaluate_all(
            "els => els.filter(e => !e.labels || e.labels.length === 0).length"
        )
        assert unlabeled_count == 0
        # AI-analyzed tags: regression | Priority: Low
        run_accessibility_scan(page)
        time.sleep(3)
        browser.close()

@pytest.mark.regression
# AI-analyzed tags: regression | Priority: Low
def TS_003_TC_003_add_new_customer_a11y_identify_input_purpose():
    import time
    import os
    from pathlib import Path as _Path
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False, slow_mo=300)

        # Attempt to restore cookies / localStorage from a Playwright storage_state file.
        # Priority: UI_STORAGE_FILE env -> backend/storage/cookies.json
        storage_file = None
        env_sf = os.getenv("UI_STORAGE_FILE", "").strip()
        if env_sf:
            storage_file = _Path(env_sf)
        else:
            backend_root = os.getenv("SMARTAI_BACKEND_ROOT", "").strip()
            guessed = None
            if backend_root:
                guessed = _Path(backend_root) / "storage" / "cookies.json"
            else:
                for parent in _Path(__file__).resolve().parents:
                    if parent.name == "backend":
                        guessed = parent / "storage" / "cookies.json"
                        break
            if guessed and guessed.exists():
                storage_file = guessed

        if storage_file and storage_file.exists():
            try:
                context = browser.new_context(storage_state=str(storage_file))
                page = context.new_page()
                print(f"[accessibility_runner] Restored storage_state from: {storage_file}")
            except Exception as e:
                print(f"[accessibility_runner] Failed to restore storage_state: {e}")
                context = browser.new_context()
                page = context.new_page()
        else:
            context = browser.new_context()
            page = context.new_page()

        _attach_page_helpers(page)
        # Patch SmartAI
        metadata_path = _SRC_ROOT / "metadata" / "after_enrichment.json"
        with open(metadata_path, "r") as f:
            actual_metadata = json.load(f)
        patch_page_with_smartai(page, actual_metadata)
        page.goto("https://bank-buddy-crm-react.lovable.app/")
        verify_bank_crm_visible(page)
        click_customers(page)
        click_add_new_customer(page)
        email_input = page.locator("input[type='email']")
        expect(email_input._locator).to_have_attribute("autocomplete", re.compile(r".*"))
        password_input = page.locator("input[type='password']")
        expect(password_input._locator).to_have_attribute("autocomplete", re.compile(r".*"))
        username_input = page.locator("input[name='username']")
        if username_input.count() > 0:
            expect(username_input._locator).to_have_attribute("autocomplete", re.compile(r".*"))
        # AI-analyzed tags: regression | Priority: Low
        run_accessibility_scan(page)
        time.sleep(3)
        browser.close()

@pytest.mark.regression
# AI-analyzed tags: regression | Priority: Low
def TS_003_TC_004_add_new_customer_a11y_keyboard_access():
    import time
    import os
    from pathlib import Path as _Path
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False, slow_mo=300)

        # Attempt to restore cookies / localStorage from a Playwright storage_state file.
        # Priority: UI_STORAGE_FILE env -> backend/storage/cookies.json
        storage_file = None
        env_sf = os.getenv("UI_STORAGE_FILE", "").strip()
        if env_sf:
            storage_file = _Path(env_sf)
        else:
            backend_root = os.getenv("SMARTAI_BACKEND_ROOT", "").strip()
            guessed = None
            if backend_root:
                guessed = _Path(backend_root) / "storage" / "cookies.json"
            else:
                for parent in _Path(__file__).resolve().parents:
                    if parent.name == "backend":
                        guessed = parent / "storage" / "cookies.json"
                        break
            if guessed and guessed.exists():
                storage_file = guessed

        if storage_file and storage_file.exists():
            try:
                context = browser.new_context(storage_state=str(storage_file))
                page = context.new_page()
                print(f"[accessibility_runner] Restored storage_state from: {storage_file}")
            except Exception as e:
                print(f"[accessibility_runner] Failed to restore storage_state: {e}")
                context = browser.new_context()
                page = context.new_page()
        else:
            context = browser.new_context()
            page = context.new_page()

        _attach_page_helpers(page)
        # Patch SmartAI
        metadata_path = _SRC_ROOT / "metadata" / "after_enrichment.json"
        with open(metadata_path, "r") as f:
            actual_metadata = json.load(f)
        patch_page_with_smartai(page, actual_metadata)
        page.goto("https://bank-buddy-crm-react.lovable.app/")
        verify_bank_crm_visible(page)
        click_customers(page)
        click_add_new_customer(page)
        before = page.evaluate("document.activeElement && document.activeElement.tagName")
        page.keyboard.press("Tab")
        after = page.evaluate("document.activeElement && document.activeElement.tagName")
        assert before != after
        # AI-analyzed tags: regression | Priority: Low
        run_accessibility_scan(page)
        time.sleep(3)
        browser.close()

@pytest.mark.regression
# AI-analyzed tags: regression | Priority: Low
def TS_003_TC_005_add_new_customer_a11y_no_keyboard_trap():
    import time
    import os
    from pathlib import Path as _Path
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False, slow_mo=300)

        # Attempt to restore cookies / localStorage from a Playwright storage_state file.
        # Priority: UI_STORAGE_FILE env -> backend/storage/cookies.json
        storage_file = None
        env_sf = os.getenv("UI_STORAGE_FILE", "").strip()
        if env_sf:
            storage_file = _Path(env_sf)
        else:
            backend_root = os.getenv("SMARTAI_BACKEND_ROOT", "").strip()
            guessed = None
            if backend_root:
                guessed = _Path(backend_root) / "storage" / "cookies.json"
            else:
                for parent in _Path(__file__).resolve().parents:
                    if parent.name == "backend":
                        guessed = parent / "storage" / "cookies.json"
                        break
            if guessed and guessed.exists():
                storage_file = guessed

        if storage_file and storage_file.exists():
            try:
                context = browser.new_context(storage_state=str(storage_file))
                page = context.new_page()
                print(f"[accessibility_runner] Restored storage_state from: {storage_file}")
            except Exception as e:
                print(f"[accessibility_runner] Failed to restore storage_state: {e}")
                context = browser.new_context()
                page = context.new_page()
        else:
            context = browser.new_context()
            page = context.new_page()

        _attach_page_helpers(page)
        # Patch SmartAI
        metadata_path = _SRC_ROOT / "metadata" / "after_enrichment.json"
        with open(metadata_path, "r") as f:
            actual_metadata = json.load(f)
        patch_page_with_smartai(page, actual_metadata)
        page.goto("https://bank-buddy-crm-react.lovable.app/")
        verify_bank_crm_visible(page)
        click_customers(page)
        click_add_new_customer(page)
        start = page.evaluate("document.activeElement && document.activeElement.tagName")
        page.keyboard.press("Tab")
        forward = page.evaluate("document.activeElement && document.activeElement.tagName")
        page.keyboard.press("Shift+Tab")
        backward = page.evaluate("document.activeElement && document.activeElement.tagName")
        assert start != forward
        assert start == backward
        # AI-analyzed tags: regression | Priority: Low
        run_accessibility_scan(page)
        time.sleep(3)
        browser.close()

@pytest.mark.regression
# AI-analyzed tags: regression | Priority: Low
def TS_003_TC_006_add_new_customer_a11y_page_title():
    import time
    import os
    from pathlib import Path as _Path
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False, slow_mo=300)

        # Attempt to restore cookies / localStorage from a Playwright storage_state file.
        # Priority: UI_STORAGE_FILE env -> backend/storage/cookies.json
        storage_file = None
        env_sf = os.getenv("UI_STORAGE_FILE", "").strip()
        if env_sf:
            storage_file = _Path(env_sf)
        else:
            backend_root = os.getenv("SMARTAI_BACKEND_ROOT", "").strip()
            guessed = None
            if backend_root:
                guessed = _Path(backend_root) / "storage" / "cookies.json"
            else:
                for parent in _Path(__file__).resolve().parents:
                    if parent.name == "backend":
                        guessed = parent / "storage" / "cookies.json"
                        break
            if guessed and guessed.exists():
                storage_file = guessed

        if storage_file and storage_file.exists():
            try:
                context = browser.new_context(storage_state=str(storage_file))
                page = context.new_page()
                print(f"[accessibility_runner] Restored storage_state from: {storage_file}")
            except Exception as e:
                print(f"[accessibility_runner] Failed to restore storage_state: {e}")
                context = browser.new_context()
                page = context.new_page()
        else:
            context = browser.new_context()
            page = context.new_page()

        _attach_page_helpers(page)
        # Patch SmartAI
        metadata_path = _SRC_ROOT / "metadata" / "after_enrichment.json"
        with open(metadata_path, "r") as f:
            actual_metadata = json.load(f)
        patch_page_with_smartai(page, actual_metadata)
        page.goto("https://bank-buddy-crm-react.lovable.app/")
        verify_bank_crm_visible(page)
        click_customers(page)
        click_add_new_customer(page)
        title = page.evaluate("document.title")
        assert title
        assert len(title) > 3
        # AI-analyzed tags: regression | Priority: Low
        run_accessibility_scan(page)
        time.sleep(3)
        browser.close()

@pytest.mark.regression
# AI-analyzed tags: regression | Priority: Low
def TS_003_TC_007_add_new_customer_a11y_language_of_page():
    import time
    import os
    from pathlib import Path as _Path
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False, slow_mo=300)

        # Attempt to restore cookies / localStorage from a Playwright storage_state file.
        # Priority: UI_STORAGE_FILE env -> backend/storage/cookies.json
        storage_file = None
        env_sf = os.getenv("UI_STORAGE_FILE", "").strip()
        if env_sf:
            storage_file = _Path(env_sf)
        else:
            backend_root = os.getenv("SMARTAI_BACKEND_ROOT", "").strip()
            guessed = None
            if backend_root:
                guessed = _Path(backend_root) / "storage" / "cookies.json"
            else:
                for parent in _Path(__file__).resolve().parents:
                    if parent.name == "backend":
                        guessed = parent / "storage" / "cookies.json"
                        break
            if guessed and guessed.exists():
                storage_file = guessed

        if storage_file and storage_file.exists():
            try:
                context = browser.new_context(storage_state=str(storage_file))
                page = context.new_page()
                print(f"[accessibility_runner] Restored storage_state from: {storage_file}")
            except Exception as e:
                print(f"[accessibility_runner] Failed to restore storage_state: {e}")
                context = browser.new_context()
                page = context.new_page()
        else:
            context = browser.new_context()
            page = context.new_page()

        _attach_page_helpers(page)
        # Patch SmartAI
        metadata_path = _SRC_ROOT / "metadata" / "after_enrichment.json"
        with open(metadata_path, "r") as f:
            actual_metadata = json.load(f)
        patch_page_with_smartai(page, actual_metadata)
        page.goto("https://bank-buddy-crm-react.lovable.app/")
        verify_bank_crm_visible(page)
        click_customers(page)
        click_add_new_customer(page)
        expect(page.locator("html")._locator).to_have_attribute("lang", re.compile(r".*"))
        # AI-analyzed tags: regression | Priority: Low
        run_accessibility_scan(page)
        time.sleep(3)
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
    if _should_run('TS_003_TC_001_add_new_customer_a11y_non_text_content'):
        try:
            print(f'\n[accessibility_runner] Running test: TS_003_TC_001_add_new_customer_a11y_non_text_content...\n')
            TS_003_TC_001_add_new_customer_a11y_non_text_content()
            print(f'\n[accessibility_runner] TS_003_TC_001_add_new_customer_a11y_non_text_content: PASS\n')
        except Exception as exc:
            failures += 1
            print(f'\n[accessibility_runner] TS_003_TC_001_add_new_customer_a11y_non_text_content: FAIL\nDetails: {exc}\n')
    else:
        print(f'\n[accessibility_runner] Skipping TS_003_TC_001_add_new_customer_a11y_non_text_content (tag filter)\n')
    if _should_run('TS_003_TC_002_add_new_customer_a11y_info_and_relationships'):
        try:
            print(f'\n[accessibility_runner] Running test: TS_003_TC_002_add_new_customer_a11y_info_and_relationships...\n')
            TS_003_TC_002_add_new_customer_a11y_info_and_relationships()
            print(f'\n[accessibility_runner] TS_003_TC_002_add_new_customer_a11y_info_and_relationships: PASS\n')
        except Exception as exc:
            failures += 1
            print(f'\n[accessibility_runner] TS_003_TC_002_add_new_customer_a11y_info_and_relationships: FAIL\nDetails: {exc}\n')
    else:
        print(f'\n[accessibility_runner] Skipping TS_003_TC_002_add_new_customer_a11y_info_and_relationships (tag filter)\n')
    if _should_run('TS_003_TC_003_add_new_customer_a11y_identify_input_purpose'):
        try:
            print(f'\n[accessibility_runner] Running test: TS_003_TC_003_add_new_customer_a11y_identify_input_purpose...\n')
            TS_003_TC_003_add_new_customer_a11y_identify_input_purpose()
            print(f'\n[accessibility_runner] TS_003_TC_003_add_new_customer_a11y_identify_input_purpose: PASS\n')
        except Exception as exc:
            failures += 1
            print(f'\n[accessibility_runner] TS_003_TC_003_add_new_customer_a11y_identify_input_purpose: FAIL\nDetails: {exc}\n')
    else:
        print(f'\n[accessibility_runner] Skipping TS_003_TC_003_add_new_customer_a11y_identify_input_purpose (tag filter)\n')
    if _should_run('TS_003_TC_004_add_new_customer_a11y_keyboard_access'):
        try:
            print(f'\n[accessibility_runner] Running test: TS_003_TC_004_add_new_customer_a11y_keyboard_access...\n')
            TS_003_TC_004_add_new_customer_a11y_keyboard_access()
            print(f'\n[accessibility_runner] TS_003_TC_004_add_new_customer_a11y_keyboard_access: PASS\n')
        except Exception as exc:
            failures += 1
            print(f'\n[accessibility_runner] TS_003_TC_004_add_new_customer_a11y_keyboard_access: FAIL\nDetails: {exc}\n')
    else:
        print(f'\n[accessibility_runner] Skipping TS_003_TC_004_add_new_customer_a11y_keyboard_access (tag filter)\n')
    if _should_run('TS_003_TC_005_add_new_customer_a11y_no_keyboard_trap'):
        try:
            print(f'\n[accessibility_runner] Running test: TS_003_TC_005_add_new_customer_a11y_no_keyboard_trap...\n')
            TS_003_TC_005_add_new_customer_a11y_no_keyboard_trap()
            print(f'\n[accessibility_runner] TS_003_TC_005_add_new_customer_a11y_no_keyboard_trap: PASS\n')
        except Exception as exc:
            failures += 1
            print(f'\n[accessibility_runner] TS_003_TC_005_add_new_customer_a11y_no_keyboard_trap: FAIL\nDetails: {exc}\n')
    else:
        print(f'\n[accessibility_runner] Skipping TS_003_TC_005_add_new_customer_a11y_no_keyboard_trap (tag filter)\n')
    if _should_run('TS_003_TC_006_add_new_customer_a11y_page_title'):
        try:
            print(f'\n[accessibility_runner] Running test: TS_003_TC_006_add_new_customer_a11y_page_title...\n')
            TS_003_TC_006_add_new_customer_a11y_page_title()
            print(f'\n[accessibility_runner] TS_003_TC_006_add_new_customer_a11y_page_title: PASS\n')
        except Exception as exc:
            failures += 1
            print(f'\n[accessibility_runner] TS_003_TC_006_add_new_customer_a11y_page_title: FAIL\nDetails: {exc}\n')
    else:
        print(f'\n[accessibility_runner] Skipping TS_003_TC_006_add_new_customer_a11y_page_title (tag filter)\n')
    if _should_run('TS_003_TC_007_add_new_customer_a11y_language_of_page'):
        try:
            print(f'\n[accessibility_runner] Running test: TS_003_TC_007_add_new_customer_a11y_language_of_page...\n')
            TS_003_TC_007_add_new_customer_a11y_language_of_page()
            print(f'\n[accessibility_runner] TS_003_TC_007_add_new_customer_a11y_language_of_page: PASS\n')
        except Exception as exc:
            failures += 1
            print(f'\n[accessibility_runner] TS_003_TC_007_add_new_customer_a11y_language_of_page: FAIL\nDetails: {exc}\n')
    else:
        print(f'\n[accessibility_runner] Skipping TS_003_TC_007_add_new_customer_a11y_language_of_page (tag filter)\n')

    if failures > 0:
        print(f'\n[accessibility_runner] Summary: {failures} test(s) failed.')
        sys.exit(1)
    else:
        print(f'\n[accessibility_runner] Summary: All tests passed.')
        sys.exit(0)
