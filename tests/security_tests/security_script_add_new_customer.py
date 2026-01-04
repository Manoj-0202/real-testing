# Auto-generated security runner
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
    "TS_001_TC_001_add_new_customer_security_xss": [],
    "TS_001_TC_002_add_new_customer_security_sqli": [],
    "TS_001_TC_003_add_new_customer_security_command_injection": [],
    "TS_001_TC_004_add_new_customer_security_input_fuzzing": [],
    "TS_001_TC_005_add_new_customer_security_headers": []
}

# AI-analyzed tags: none | Priority: Low
def TS_001_TC_001_add_new_customer_security_xss():
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
                print(f"[security_runner] Restored storage_state from: {storage_file}")
            except Exception as e:
                print(f"[security_runner] Failed to restore storage_state: {e}")
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
        dialogs = []
        page.on("dialog", lambda d: dialogs.append(d.message))

        click_customers(page)
        click_add_new_customer(page)

        xss_payloads = [
            "<script>alert('XSS')</script>",
            '"><img src=x onerror=alert("XSS")>',
            "<svg/onload=alert(1)>",
            "<iframe src=javascript:alert(1)>"
        ]

        for payload in xss_payloads:
            enter_full_name(page, payload)
            enter_email(page, payload)
            enter_phone_number(page, payload)
            enter_address(page, payload)
            enter_occupation(page, payload)
            enter_annual_income(page, payload)
            enter_initial_deposit(page, payload)

        click_add_customer(page)
        assert not dialogs
        # AI-analyzed tags: none | Priority: Low
        time.sleep(3)
        browser.close()

# AI-analyzed tags: none | Priority: Low
def TS_001_TC_002_add_new_customer_security_sqli():
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
                print(f"[security_runner] Restored storage_state from: {storage_file}")
            except Exception as e:
                print(f"[security_runner] Failed to restore storage_state: {e}")
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

        sqli_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' UNION SELECT NULL,NULL --",
            "'; DROP TABLE users; --"
        ]

        for payload in sqli_payloads:
            enter_full_name(page, payload)
            enter_email(page, payload)
            enter_phone_number(page, payload)
            enter_address(page, payload)
            enter_occupation(page, payload)
            enter_annual_income(page, payload)
            enter_initial_deposit(page, payload)

        click_add_customer(page)
        assert "SQL" not in page.content()
        # AI-analyzed tags: none | Priority: Low
        time.sleep(3)
        browser.close()

# AI-analyzed tags: none | Priority: Low
def TS_001_TC_003_add_new_customer_security_command_injection():
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
                print(f"[security_runner] Restored storage_state from: {storage_file}")
            except Exception as e:
                print(f"[security_runner] Failed to restore storage_state: {e}")
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

        command_injection_payloads = [
            "; ls",
            "&& whoami",
            "| cat /etc/passwd",
            "$(whoami)",
            "`whoami`"
        ]

        for payload in command_injection_payloads:
            enter_full_name(page, payload)
            enter_email(page, payload)
            enter_phone_number(page, payload)
            enter_address(page, payload)
            enter_occupation(page, payload)
            enter_annual_income(page, payload)
            enter_initial_deposit(page, payload)

        click_add_customer(page)
        assert page.url() != ""
        # AI-analyzed tags: none | Priority: Low
        time.sleep(3)
        browser.close()

# AI-analyzed tags: none | Priority: Low
def TS_001_TC_004_add_new_customer_security_input_fuzzing():
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
                print(f"[security_runner] Restored storage_state from: {storage_file}")
            except Exception as e:
                print(f"[security_runner] Failed to restore storage_state: {e}")
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

        fuzzing_payloads = [
            "A" * 5000,
            "B" * 10000,
            "@#$%^&*()" * 200,
            "9" * 100
        ]

        for payload in fuzzing_payloads:
            enter_full_name(page, payload)
            enter_email(page, payload)
            enter_phone_number(page, payload)
            enter_address(page, payload)
            enter_occupation(page, payload)
            enter_annual_income(page, payload)
            enter_initial_deposit(page, payload)

        click_add_customer(page)
        assert page.url() != ""
        # AI-analyzed tags: none | Priority: Low
        time.sleep(3)
        browser.close()

# AI-analyzed tags: none | Priority: Low
def TS_001_TC_005_add_new_customer_security_headers():
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
                print(f"[security_runner] Restored storage_state from: {storage_file}")
            except Exception as e:
                print(f"[security_runner] Failed to restore storage_state: {e}")
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
        response = page.goto("https://bank-buddy-crm-react.lovable.app/")
        headers = response.headers or {}

        assert "content-security-policy" in headers
        assert "x-frame-options" in headers
        assert "x-content-type-options" in headers
        if page.url().startswith("https"):
            assert "strict-transport-security" in headers
        # AI-analyzed tags: none | Priority: Low
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
    if _should_run('TS_001_TC_001_add_new_customer_security_xss'):
        try:
            print(f'\n[security_runner] Running test: TS_001_TC_001_add_new_customer_security_xss...\n')
            TS_001_TC_001_add_new_customer_security_xss()
            print(f'\n[security_runner] TS_001_TC_001_add_new_customer_security_xss: PASS\n')
        except Exception as exc:
            failures += 1
            print(f'\n[security_runner] TS_001_TC_001_add_new_customer_security_xss: FAIL\nDetails: {exc}\n')
    else:
        print(f'\n[security_runner] Skipping TS_001_TC_001_add_new_customer_security_xss (tag filter)\n')
    if _should_run('TS_001_TC_002_add_new_customer_security_sqli'):
        try:
            print(f'\n[security_runner] Running test: TS_001_TC_002_add_new_customer_security_sqli...\n')
            TS_001_TC_002_add_new_customer_security_sqli()
            print(f'\n[security_runner] TS_001_TC_002_add_new_customer_security_sqli: PASS\n')
        except Exception as exc:
            failures += 1
            print(f'\n[security_runner] TS_001_TC_002_add_new_customer_security_sqli: FAIL\nDetails: {exc}\n')
    else:
        print(f'\n[security_runner] Skipping TS_001_TC_002_add_new_customer_security_sqli (tag filter)\n')
    if _should_run('TS_001_TC_003_add_new_customer_security_command_injection'):
        try:
            print(f'\n[security_runner] Running test: TS_001_TC_003_add_new_customer_security_command_injection...\n')
            TS_001_TC_003_add_new_customer_security_command_injection()
            print(f'\n[security_runner] TS_001_TC_003_add_new_customer_security_command_injection: PASS\n')
        except Exception as exc:
            failures += 1
            print(f'\n[security_runner] TS_001_TC_003_add_new_customer_security_command_injection: FAIL\nDetails: {exc}\n')
    else:
        print(f'\n[security_runner] Skipping TS_001_TC_003_add_new_customer_security_command_injection (tag filter)\n')
    if _should_run('TS_001_TC_004_add_new_customer_security_input_fuzzing'):
        try:
            print(f'\n[security_runner] Running test: TS_001_TC_004_add_new_customer_security_input_fuzzing...\n')
            TS_001_TC_004_add_new_customer_security_input_fuzzing()
            print(f'\n[security_runner] TS_001_TC_004_add_new_customer_security_input_fuzzing: PASS\n')
        except Exception as exc:
            failures += 1
            print(f'\n[security_runner] TS_001_TC_004_add_new_customer_security_input_fuzzing: FAIL\nDetails: {exc}\n')
    else:
        print(f'\n[security_runner] Skipping TS_001_TC_004_add_new_customer_security_input_fuzzing (tag filter)\n')
    if _should_run('TS_001_TC_005_add_new_customer_security_headers'):
        try:
            print(f'\n[security_runner] Running test: TS_001_TC_005_add_new_customer_security_headers...\n')
            TS_001_TC_005_add_new_customer_security_headers()
            print(f'\n[security_runner] TS_001_TC_005_add_new_customer_security_headers: PASS\n')
        except Exception as exc:
            failures += 1
            print(f'\n[security_runner] TS_001_TC_005_add_new_customer_security_headers: FAIL\nDetails: {exc}\n')
    else:
        print(f'\n[security_runner] Skipping TS_001_TC_005_add_new_customer_security_headers (tag filter)\n')

    if failures > 0:
        print(f'\n[security_runner] Summary: {failures} test(s) failed.')
        sys.exit(1)
    else:
        print(f'\n[security_runner] Summary: All tests passed.')
        sys.exit(0)
