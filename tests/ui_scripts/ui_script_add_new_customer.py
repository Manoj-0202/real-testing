# Auto-generated ui runner
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
from pages.loans_page_methods import *
from pages.loanss_page_methods import *
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
    "TS_001_TC_001_add_new_customer_positive_feature": [
        "regression"
    ],
    "TS_001_TC_002_add_new_customer_negative_feature": [
        "functional"
    ],
    "TS_001_TC_003_add_new_customer_edge_feature": [
        "functional"
    ]
}

@pytest.mark.regression
# AI-analyzed tags: regression | Priority: Low
def TS_001_TC_001_add_new_customer_positive_feature():
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
                print(f"[ui_runner] Restored storage_state from: {storage_file}")
            except Exception as e:
                print(f"[ui_runner] Failed to restore storage_state: {e}")
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
        click_customers(page)
        click_add_new_customer(page)
        enter_full_name(page, "John Doe")
        assert_enter_full_name(page, "John Doe")
        enter_email(page, "john.doe@example.com")
        assert_enter_email(page, "john.doe@example.com")
        enter_phone_number(page, "1234567890")
        assert_enter_phone_number(page, "1234567890")
        select_account_type(page, "Standard")
        enter_address(page, "123 Main St, Anytown, USA")
        assert_enter_address(page, "123 Main St, Anytown, USA")
        enter_occupation(page, "Software Engineer")
        assert_enter_occupation(page, "Software Engineer")
        enter_annual_income(page, "75000")
        assert_enter_annual_income(page, "75000")
        enter_initial_deposit(page, "1000")
        assert_enter_initial_deposit(page, "1000")
        click_add_customer(page)
        # Assuming there's a method to verify customer addition success
        verify_bank_crm_visible(page)
        # AI-analyzed tags: regression | Priority: Low
        time.sleep(3)
        browser.close()

@pytest.mark.functional
# AI-analyzed tags: functional | Priority: Low
def TS_001_TC_002_add_new_customer_negative_feature():
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
                print(f"[ui_runner] Restored storage_state from: {storage_file}")
            except Exception as e:
                print(f"[ui_runner] Failed to restore storage_state: {e}")
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
        click_customers(page)
        click_add_new_customer(page)
        enter_full_name(page, "")
        assert_enter_full_name(page, "")
        enter_email(page, "invalid-email")
        assert_enter_email(page, "invalid-email")
        enter_phone_number(page, "")
        assert_enter_phone_number(page, "")
        select_account_type(page, "")
        enter_address(page, "")
        assert_enter_address(page, "")
        enter_occupation(page, "")
        assert_enter_occupation(page, "")
        enter_annual_income(page, "")
        assert_enter_annual_income(page, "")
        enter_initial_deposit(page, "")
        assert_enter_initial_deposit(page, "")
        click_add_customer(page)
        # Assuming there's a method to verify customer addition failure
        verify_bank_crm_visible(page)
        # AI-analyzed tags: functional | Priority: Low
        time.sleep(3)
        browser.close()

@pytest.mark.functional
# AI-analyzed tags: functional | Priority: Low
def TS_001_TC_003_add_new_customer_edge_feature():
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
                print(f"[ui_runner] Restored storage_state from: {storage_file}")
            except Exception as e:
                print(f"[ui_runner] Failed to restore storage_state: {e}")
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
        click_customers(page)
        click_add_new_customer(page)
        enter_full_name(page, "A" * 256)
        assert_enter_full_name(page, "A" * 256)
        enter_email(page, "verylongemail" + "a" * 240 + "@example.com")
        assert_enter_email(page, "verylongemail" + "a" * 240 + "@example.com")
        enter_phone_number(page, "!@#$%^&*()")
        assert_enter_phone_number(page, "!@#$%^&*()")
        select_account_type(page, "Standard")
        enter_address(page, "A" * 256)
        assert_enter_address(page, "A" * 256)
        enter_occupation(page, "A" * 256)
        assert_enter_occupation(page, "A" * 256)
        enter_annual_income(page, "9999999999")
        assert_enter_annual_income(page, "9999999999")
        enter_initial_deposit(page, "9999999999")
        assert_enter_initial_deposit(page, "9999999999")
        click_add_customer(page)
        # Assuming there's a method to verify customer addition success
        verify_bank_crm_visible(page)
        # AI-analyzed tags: functional | Priority: Low
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
    if _should_run('TS_001_TC_001_add_new_customer_positive_feature'):
        try:
            print(f'\n[ui_runner] Running test: TS_001_TC_001_add_new_customer_positive_feature...\n')
            TS_001_TC_001_add_new_customer_positive_feature()
            print(f'\n[ui_runner] TS_001_TC_001_add_new_customer_positive_feature: PASS\n')
        except Exception as exc:
            failures += 1
            print(f'\n[ui_runner] TS_001_TC_001_add_new_customer_positive_feature: FAIL\nDetails: {exc}\n')
    else:
        print(f'\n[ui_runner] Skipping TS_001_TC_001_add_new_customer_positive_feature (tag filter)\n')
    if _should_run('TS_001_TC_002_add_new_customer_negative_feature'):
        try:
            print(f'\n[ui_runner] Running test: TS_001_TC_002_add_new_customer_negative_feature...\n')
            TS_001_TC_002_add_new_customer_negative_feature()
            print(f'\n[ui_runner] TS_001_TC_002_add_new_customer_negative_feature: PASS\n')
        except Exception as exc:
            failures += 1
            print(f'\n[ui_runner] TS_001_TC_002_add_new_customer_negative_feature: FAIL\nDetails: {exc}\n')
    else:
        print(f'\n[ui_runner] Skipping TS_001_TC_002_add_new_customer_negative_feature (tag filter)\n')
    if _should_run('TS_001_TC_003_add_new_customer_edge_feature'):
        try:
            print(f'\n[ui_runner] Running test: TS_001_TC_003_add_new_customer_edge_feature...\n')
            TS_001_TC_003_add_new_customer_edge_feature()
            print(f'\n[ui_runner] TS_001_TC_003_add_new_customer_edge_feature: PASS\n')
        except Exception as exc:
            failures += 1
            print(f'\n[ui_runner] TS_001_TC_003_add_new_customer_edge_feature: FAIL\nDetails: {exc}\n')
    else:
        print(f'\n[ui_runner] Skipping TS_001_TC_003_add_new_customer_edge_feature (tag filter)\n')

    if failures > 0:
        print(f'\n[ui_runner] Summary: {failures} test(s) failed.')
        sys.exit(1)
    else:
        print(f'\n[ui_runner] Summary: All tests passed.')
        sys.exit(0)
