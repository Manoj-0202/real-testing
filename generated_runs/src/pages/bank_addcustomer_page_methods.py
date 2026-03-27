import re
import os
from playwright.sync_api import expect
 
def _ci(s):  # case-insensitive canonical
    return (s or "").strip().lower()
 
def _digits_only(s):
    return re.sub(r"\D+", "", (s or ""))
 
def _values_match(actual, expected):
    a = "" if actual is None else str(actual)
    e = "" if expected is None else str(expected)
    if _ci(a) == _ci(e):
        return True
    da = _digits_only(a)
    de = _digits_only(e)
    return bool(da and de and da == de)
 
def _safe_input_value(locator):
    if locator is None:
        return None
    getters = (
        lambda: locator.input_value(),
        lambda: locator.evaluate("el => el ? (el.value || el.innerText || el.textContent) : null"),
        lambda: locator.inner_text(),
    )
    for getter in getters:
        try:
            value = getter()
            if value is not None:
                return value
        except Exception:
            continue
    return None

def _check_by_label(page, label, checked=True):
    exact_re = re.compile(r"^\s*" + re.escape(label) + r"\s*$", re.I)
    strategies = (
        lambda: page.get_by_label(label, exact=True).first,
        lambda: page.get_by_role("radio", name=label, exact=True).first,
        lambda: page.get_by_role("checkbox", name=label, exact=True).first,
        lambda: page.get_by_text(label, exact=True).first,
        lambda: page.locator("label").filter(has_text=exact_re).locator(
            "input[type='checkbox'], input[type='radio'], [role='checkbox'], [role='radio']"
        ).first,
    )
    for factory in strategies:
        try:
            locator = factory()
            if locator.count() == 0:
                continue
            try:
                locator.scroll_into_view_if_needed(timeout=1000)
            except Exception:
                pass
            try:
                if checked:
                    locator.check()
                else:
                    locator.uncheck()
                return
            except Exception:
                locator.click()
                return
        except Exception:
            continue
    raise RuntimeError(f"Unable to {'check' if checked else 'uncheck'} option: {label}")

def _find_frame_for_field(page, label=None, placeholder=None):
    frames = getattr(page, "frames", []) or []
    for frame in frames:
        if label:
            try:
                locator = frame.get_by_label(label)
                if locator.count() > 0:
                    return frame
            except Exception:
                pass
            try:
                locator = frame.get_by_label(re.compile(r"^\s*" + re.escape(label) + r"\s*$", re.I))
                if locator.count() > 0:
                    return frame
            except Exception:
                pass
        if placeholder:
            try:
                locator = frame.get_by_placeholder(placeholder)
                if locator.count() > 0:
                    return frame
            except Exception:
                pass
    return None

def _safe_locator_text(locator):
    if locator is None:
        return None
    getters = (
        lambda: _safe_input_value(locator),
        lambda: locator.text_content(),
        lambda: locator.inner_text(),
        lambda: locator.evaluate("el => el ? (el.innerText || el.textContent || el.value) : null"),
    )
    for getter in getters:
        try:
            value = getter()
            if value is not None:
                return value
        except Exception:
            continue
    return None

def _dismiss_open_dropdowns(page):
    try:
        listbox = page.get_by_role("listbox").first
        if listbox.count() > 0 and listbox.is_visible(timeout=500):
            try:
                page.keyboard.press("Escape")
            except Exception:
                pass
    except Exception:
        pass

def _placeholder_variants(label, placeholder=None):
    values = []
    if placeholder:
        values.append(placeholder)
    base = (label or "").replace("*", "").strip()
    if base:
        values.append(base)
        values.append(f"Enter {base}")
        values.append(f"Enter {base.lower()}")
        values.append(f"Enter {base.title()}")
        words = [w for w in re.split(r"\s+", base) if w]
        if words:
            values.append(f"Enter {words[0]}")
            values.append(f"Enter {words[0].lower()}")
            values.append(f"Enter {words[0].title()}")
        if " on " in base.lower():
            first_chunk = re.split(r"\bon\b", base, flags=re.I)[0].strip()
            if first_chunk:
                values.append(first_chunk)
                values.append(f"Enter {first_chunk}")
    seen = set()
    out = []
    for item in values:
        key = (item or "").strip()
        if not key:
            continue
        norm = key.lower()
        if norm in seen:
            continue
        seen.add(norm)
        out.append(key)
    return out

def _xpath_literal(text):
    value = str(text or "")
    if "'" not in value:
        return "'" + value + "'"
    if '"' not in value:
        return '"' + value + '"'
    parts = value.split("'")
    items = []
    for index, part in enumerate(parts):
        items.append("'" + part + "'")
        if index != len(parts) - 1:
            items.append('"\'"')
    return "concat(" + ", ".join(items) + ")"

def _select_timeout_ms():
    try:
        return int(os.getenv("SMARTAI_SELECT_TIMEOUT_MS", "2000"))
    except Exception:
        return 2000

def _select_fast_mode():
    return os.getenv("SMARTAI_SELECT_FAST", "").strip().lower() in ("1", "true", "yes", "y", "on")

def _select_by_label(page, label, value):
    target_page = _find_frame_for_field(page, label=label) or page
    exact_label_re = re.compile(r"^\s*" + re.escape(label) + r"\s*$", re.I)
    option_re = re.compile(r"^\s*" + re.escape(str(value)) + r"\s*$", re.I)
    x_label = _xpath_literal(label)
    opened_dropdown = False
    timeout_ms = _select_timeout_ms()
    fast_mode = _select_fast_mode()
    direct_targets = []
    try:
        direct_targets.append(target_page.get_by_label(label, exact=True).first)
    except Exception:
        pass
    try:
        direct_targets.append(target_page.get_by_label(exact_label_re).first)
    except Exception:
        pass
    if not fast_mode:
        for ph in _placeholder_variants(label, label):
            scoped_page = _find_frame_for_field(page, placeholder=ph) or target_page
            try:
                direct_targets.append(scoped_page.get_by_placeholder(ph).first)
            except Exception:
                pass
    try:
        direct_targets.append(target_page.get_by_role("combobox", name=label, exact=True).first)
    except Exception:
        pass
    try:
        direct_targets.append(target_page.get_by_role("combobox", name=exact_label_re).first)
    except Exception:
        pass
    if not fast_mode:
        try:
            direct_targets.append(
                target_page.locator(
                    "xpath=//*[normalize-space()=" + x_label + "]"
                    "/following::*[self::select or @role='combobox'][1]"
                ).first
            )
        except Exception:
            pass
        try:
            direct_targets.append(
                target_page.locator(
                    "xpath=//*[contains(translate(normalize-space(.),"
                    "'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),"
                    + _xpath_literal(str(label).strip().lower()) + ")]"
                    "/following::*[self::select or @role='combobox'][1]"
                ).first
            )
        except Exception:
            pass

    for locator in direct_targets:
        try:
            if locator.count() == 0:
                continue
            current_value = _safe_locator_text(locator)
            if _values_match(current_value, str(value)):
                _dismiss_open_dropdowns(page)
                return
            try:
                locator.scroll_into_view_if_needed(timeout=min(1000, timeout_ms))
            except Exception:
                pass
            try:
                locator.select_option(label=str(value), timeout=timeout_ms)
                _dismiss_open_dropdowns(page)
                return
            except Exception:
                pass
            try:
                locator.select_option(value=str(value), timeout=timeout_ms)
                _dismiss_open_dropdowns(page)
                return
            except Exception:
                pass
            try:
                locator.select_option(str(value), timeout=timeout_ms)
                _dismiss_open_dropdowns(page)
                return
            except Exception:
                pass
            if opened_dropdown:
                continue
            try:
                locator.click(timeout=timeout_ms)
                opened_dropdown = True
            except Exception:
                pass
        except Exception:
            continue

    if fast_mode:
        option_strategies = (
            lambda: target_page.get_by_role("option", name=str(value), exact=True).first,
            lambda: target_page.get_by_role("option", name=option_re).first,
        )
    else:
        option_strategies = (
            lambda: target_page.get_by_role("option", name=str(value), exact=True).first,
            lambda: target_page.get_by_role("option", name=option_re).first,
            lambda: target_page.get_by_role("radio", name=str(value), exact=True).first,
            lambda: target_page.get_by_role("checkbox", name=str(value), exact=True).first,
            lambda: target_page.get_by_label(str(value), exact=True).first,
            lambda: target_page.locator(
                "xpath=(//*[normalize-space()=" + x_label + "]"
                "/following::*[normalize-space()=" + _xpath_literal(str(value)) + "])[1]"
            ).first,
        )
    for factory in option_strategies:
        try:
            locator = factory()
            if locator.count() == 0:
                continue
            try:
                locator.scroll_into_view_if_needed(timeout=min(1000, timeout_ms))
            except Exception:
                pass
            try:
                locator.check(timeout=timeout_ms)
                _dismiss_open_dropdowns(page)
                return
            except Exception:
                pass
            locator.click(timeout=timeout_ms)
            _dismiss_open_dropdowns(page)
            return
        except Exception:
            continue
    raise RuntimeError(f"Unable to select {value!r} for {label!r}")

def _click_by_label(page, label):
    exact_re = re.compile(r"^\s*" + re.escape(label) + r"\s*$", re.I)
    _dismiss_open_dropdowns(page)
    strategies = (
        lambda: page.get_by_role("button", name=label, exact=True).first,
        lambda: page.locator("button").filter(has_text=exact_re).first,
        lambda: page.get_by_role("link", name=label, exact=True).first,
        lambda: page.get_by_text(label, exact=True).first,
        lambda: page.get_by_text(exact_re).first,
        lambda: page.locator("text=/^\\s*" + re.escape(label) + "\\s*$/i").first,
    )
    for factory in strategies:
        try:
            locator = factory()
            if locator.count() == 0:
                continue
            try:
                locator.scroll_into_view_if_needed(timeout=1000)
            except Exception:
                pass
            locator.click()
            return
        except Exception:
            continue
    raise RuntimeError(f"Unable to click action: {label}")

def _enter_value(page, label, value, placeholder=None):
    locators = []
    try:
        locators.append(page.get_by_label(label, exact=True).first)
    except Exception:
        pass
    try:
        locators.append(page.get_by_label(re.compile(r"^\s*" + re.escape(label) + r"\s*$", re.I)).first)
    except Exception:
        pass
    for ph in _placeholder_variants(label, placeholder):
        try:
            scoped_page = _find_frame_for_field(page, placeholder=ph) or page
            locators.append(scoped_page.get_by_placeholder(ph).first)
        except Exception:
            pass
    for locator in locators:
        try:
            if locator.count() == 0:
                continue
            try:
                locator.scroll_into_view_if_needed(timeout=1000)
            except Exception:
                pass
            locator.click()
            try:
                locator.clear()
            except Exception:
                pass
            try:
                locator.press_sequentially(str(value))
            except Exception:
                locator.fill(str(value))
            return
        except Exception:
            continue
    raise RuntimeError(f"Unable to enter value for: {label}")


def enter_full_name(page, value):
    try:
        _enter_value(page, 'Full Name', value, placeholder='Full Name')
        return
    except Exception:
        pass
    try:
        locator = page.smartAI('bank_addcustomer_full_name_textbox_full_name_field')
        locator.click()
        try:
            locator.clear()
        except Exception:
            pass
        try:
            locator.press_sequentially(str(value))
        except Exception:
            locator.fill(str(value))
        return
    except Exception:
        pass
    raise RuntimeError(f"Unable to enter value for: 'Full Name'")

def assert_enter_full_name(page, expected: str, timeout: int = 6000):
    locator = page.smartAI('bank_addcustomer_full_name_textbox_full_name_field')
    try:
        expect(locator).to_have_value(str(expected), timeout=timeout)
    except Exception as e:
        actual = _safe_input_value(locator)
        if not _values_match(actual, str(expected)):
            raise AssertionError(f"Assertion failed for 'bank_addcustomer_full_name_textbox_full_name_field' expecting '{str(expected)}' but got '{actual}': {e}")


def assert_enter_full_name_visible(page, timeout: int = 6000):
    expect(page.smartAI('bank_addcustomer_full_name_textbox_full_name_field')).to_be_visible(timeout=timeout)


def enter_email(page, value):
    try:
        _enter_value(page, 'Email', value, placeholder='Email')
        return
    except Exception:
        pass
    try:
        locator = page.smartAI('bank_addcustomer_email_textbox_email_field')
        locator.click()
        try:
            locator.clear()
        except Exception:
            pass
        try:
            locator.press_sequentially(str(value))
        except Exception:
            locator.fill(str(value))
        return
    except Exception:
        pass
    raise RuntimeError(f"Unable to enter value for: 'Email'")

def assert_enter_email(page, expected: str, timeout: int = 6000):
    locator = page.smartAI('bank_addcustomer_email_textbox_email_field')
    try:
        expect(locator).to_have_value(str(expected), timeout=timeout)
    except Exception as e:
        actual = _safe_input_value(locator)
        if not _values_match(actual, str(expected)):
            raise AssertionError(f"Assertion failed for 'bank_addcustomer_email_textbox_email_field' expecting '{str(expected)}' but got '{actual}': {e}")


def assert_enter_email_visible(page, timeout: int = 6000):
    expect(page.smartAI('bank_addcustomer_email_textbox_email_field')).to_be_visible(timeout=timeout)


def enter_phone_number(page, value):
    try:
        _enter_value(page, 'Phone Number', value, placeholder='Phone Number')
        return
    except Exception:
        pass
    try:
        locator = page.smartAI('bank_addcustomer_phone_number_textbox_phone_number_field')
        locator.click()
        try:
            locator.clear()
        except Exception:
            pass
        try:
            locator.press_sequentially(str(value))
        except Exception:
            locator.fill(str(value))
        return
    except Exception:
        pass
    raise RuntimeError(f"Unable to enter value for: 'Phone Number'")

def assert_enter_phone_number(page, expected: str, timeout: int = 6000):
    locator = page.smartAI('bank_addcustomer_phone_number_textbox_phone_number_field')
    try:
        expect(locator).to_have_value(str(expected), timeout=timeout)
    except Exception as e:
        actual = _safe_input_value(locator)
        if not _values_match(actual, str(expected)):
            raise AssertionError(f"Assertion failed for 'bank_addcustomer_phone_number_textbox_phone_number_field' expecting '{str(expected)}' but got '{actual}': {e}")


def assert_enter_phone_number_visible(page, timeout: int = 6000):
    expect(page.smartAI('bank_addcustomer_phone_number_textbox_phone_number_field')).to_be_visible(timeout=timeout)


def select_account_type(page, value):
    try:
        page.smartAI('bank_addcustomer_account_type_select_account_type_select').select_option(value)
        return
    except Exception:
        pass
    _select_by_label(page, 'Account Type', value)
    raise RuntimeError(f"Unable to select {value!r} for: 'Account Type'")

def assert_select_account_type_visible(page, timeout: int = 6000):
    expect(page.smartAI('bank_addcustomer_account_type_select_account_type_select')).to_be_visible(timeout=timeout)


def enter_address(page, value):
    try:
        _enter_value(page, 'Address', value, placeholder='Address')
        return
    except Exception:
        pass
    try:
        locator = page.smartAI('bank_addcustomer_address_textbox_address_field')
        locator.click()
        try:
            locator.clear()
        except Exception:
            pass
        try:
            locator.press_sequentially(str(value))
        except Exception:
            locator.fill(str(value))
        return
    except Exception:
        pass
    raise RuntimeError(f"Unable to enter value for: 'Address'")

def assert_enter_address(page, expected: str, timeout: int = 6000):
    locator = page.smartAI('bank_addcustomer_address_textbox_address_field')
    try:
        expect(locator).to_have_value(str(expected), timeout=timeout)
    except Exception as e:
        actual = _safe_input_value(locator)
        if not _values_match(actual, str(expected)):
            raise AssertionError(f"Assertion failed for 'bank_addcustomer_address_textbox_address_field' expecting '{str(expected)}' but got '{actual}': {e}")


def assert_enter_address_visible(page, timeout: int = 6000):
    expect(page.smartAI('bank_addcustomer_address_textbox_address_field')).to_be_visible(timeout=timeout)


def enter_occupation(page, value):
    try:
        _enter_value(page, 'Occupation', value, placeholder='Occupation')
        return
    except Exception:
        pass
    try:
        locator = page.smartAI('bank_addcustomer_occupation_textbox_occupation_field')
        locator.click()
        try:
            locator.clear()
        except Exception:
            pass
        try:
            locator.press_sequentially(str(value))
        except Exception:
            locator.fill(str(value))
        return
    except Exception:
        pass
    raise RuntimeError(f"Unable to enter value for: 'Occupation'")

def assert_enter_occupation(page, expected: str, timeout: int = 6000):
    locator = page.smartAI('bank_addcustomer_occupation_textbox_occupation_field')
    try:
        expect(locator).to_have_value(str(expected), timeout=timeout)
    except Exception as e:
        actual = _safe_input_value(locator)
        if not _values_match(actual, str(expected)):
            raise AssertionError(f"Assertion failed for 'bank_addcustomer_occupation_textbox_occupation_field' expecting '{str(expected)}' but got '{actual}': {e}")


def assert_enter_occupation_visible(page, timeout: int = 6000):
    expect(page.smartAI('bank_addcustomer_occupation_textbox_occupation_field')).to_be_visible(timeout=timeout)


def enter_annual_income(page, value):
    try:
        _enter_value(page, 'Annual Income', value, placeholder='Annual Income')
        return
    except Exception:
        pass
    try:
        locator = page.smartAI('bank_addcustomer_annual_income_textbox_annual_income_field')
        locator.click()
        try:
            locator.clear()
        except Exception:
            pass
        try:
            locator.press_sequentially(str(value))
        except Exception:
            locator.fill(str(value))
        return
    except Exception:
        pass
    raise RuntimeError(f"Unable to enter value for: 'Annual Income'")

def assert_enter_annual_income(page, expected: str, timeout: int = 6000):
    locator = page.smartAI('bank_addcustomer_annual_income_textbox_annual_income_field')
    try:
        expect(locator).to_have_value(str(expected), timeout=timeout)
    except Exception as e:
        actual = _safe_input_value(locator)
        if not _values_match(actual, str(expected)):
            raise AssertionError(f"Assertion failed for 'bank_addcustomer_annual_income_textbox_annual_income_field' expecting '{str(expected)}' but got '{actual}': {e}")


def assert_enter_annual_income_visible(page, timeout: int = 6000):
    expect(page.smartAI('bank_addcustomer_annual_income_textbox_annual_income_field')).to_be_visible(timeout=timeout)


def enter_initial_deposit(page, value):
    try:
        _enter_value(page, 'Initial Deposit', value, placeholder='Initial Deposit')
        return
    except Exception:
        pass
    try:
        locator = page.smartAI('bank_addcustomer_initial_deposit_textbox_initial_deposit_field')
        locator.click()
        try:
            locator.clear()
        except Exception:
            pass
        try:
            locator.press_sequentially(str(value))
        except Exception:
            locator.fill(str(value))
        return
    except Exception:
        pass
    raise RuntimeError(f"Unable to enter value for: 'Initial Deposit'")

def assert_enter_initial_deposit(page, expected: str, timeout: int = 6000):
    locator = page.smartAI('bank_addcustomer_initial_deposit_textbox_initial_deposit_field')
    try:
        expect(locator).to_have_value(str(expected), timeout=timeout)
    except Exception as e:
        actual = _safe_input_value(locator)
        if not _values_match(actual, str(expected)):
            raise AssertionError(f"Assertion failed for 'bank_addcustomer_initial_deposit_textbox_initial_deposit_field' expecting '{str(expected)}' but got '{actual}': {e}")


def assert_enter_initial_deposit_visible(page, timeout: int = 6000):
    expect(page.smartAI('bank_addcustomer_initial_deposit_textbox_initial_deposit_field')).to_be_visible(timeout=timeout)


def click_cancel(page):
    try:
        page.get_by_role("button", name='Cancel', exact=True).first.click()
        return
    except Exception:
        pass
    try:
        page.get_by_role("link", name='Cancel', exact=True).first.click()
        return
    except Exception:
        pass
    try:
        page.smartAI('bank_addcustomer_cancel_button_cancel_action').click()
        return
    except Exception:
        pass
    _click_by_label(page, 'Cancel')

def assert_click_cancel_visible(page, timeout: int = 6000):
    expect(page.smartAI('bank_addcustomer_cancel_button_cancel_action')).to_be_visible(timeout=timeout)


def click_add_customer(page):
    try:
        page.get_by_role("button", name='Add Customer', exact=True).first.click()
        return
    except Exception:
        pass
    try:
        page.get_by_role("link", name='Add Customer', exact=True).first.click()
        return
    except Exception:
        pass
    try:
        page.smartAI('bank_addcustomer_add_customer_button_add_customer_action').click()
        return
    except Exception:
        pass
    _click_by_label(page, 'Add Customer')

def assert_click_add_customer_visible(page, timeout: int = 6000):
    expect(page.smartAI('bank_addcustomer_add_customer_button_add_customer_action')).to_be_visible(timeout=timeout)



# ---- Allure step wrapper (added automatically) ----
try:
    import allure
except Exception:
    from contextlib import nullcontext
    class _AllureShim:
        def step(self, name):
            return nullcontext()
    allure = _AllureShim()

try:
    _step_prefixes = ('enter_', 'click_', 'select_', 'verify_', 'toggle_', 'hover_', 'upload_', 'check_', 'uncheck_', 'drag_', 'assert_')
    for _name, _obj in list(globals().items()):
        if callable(_obj) and any(_name.startswith(p) for p in _step_prefixes):
            def _make_wrapped(f, display_name=_name):
                def _wrapped(*a, **kw):
                    try:
                        dyn = getattr(allure, 'dynamic', None)
                        param_fn = None
                        if dyn and hasattr(dyn, 'parameter'):
                            param_fn = dyn.parameter
                        elif hasattr(allure, 'parameter'):
                            param_fn = allure.parameter
                        if param_fn:
                            start_idx = 1 if len(a) and getattr(a[0], '__class__', None) and getattr(a[0].__class__, '__name__', '').lower().find('page') != -1 else 0
                            for i, val in enumerate(a[start_idx:], start=1):
                                try:
                                    param_fn(f"{display_name}_arg{i}", str(val))
                                except Exception:
                                    pass
                            for k, v in kw.items():
                                try:
                                    param_fn(str(k), str(v))
                                except Exception:
                                    pass
                    except Exception:
                        pass
                    with allure.step(display_name):
                        return f(*a, **kw)
                return _wrapped
            globals()[_name] = _make_wrapped(_obj)
except Exception:
    pass
# ---- end wrapper ----
