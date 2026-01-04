import re
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


def enter_full_name(page, value):
    page.smartAI('bank_add_customer_full_name_textbox_full_name_field').fill(str(value))

def assert_enter_full_name(page, expected: str, timeout: int = 6000):
    locator = page.smartAI('bank_add_customer_full_name_textbox_full_name_field')
    try:
        expect(locator).to_have_value(str(expected), timeout=timeout)
    except Exception as e:
        actual = _safe_input_value(locator)
        if not _values_match(actual, str(expected)):
            raise AssertionError(f"Assertion failed for 'bank_add_customer_full_name_textbox_full_name_field' expecting '{str(expected)}' but got '{actual}': {e}")


def enter_email(page, value):
    page.smartAI('bank_add_customer_email_textbox_email_field').fill(str(value))

def assert_enter_email(page, expected: str, timeout: int = 6000):
    locator = page.smartAI('bank_add_customer_email_textbox_email_field')
    try:
        expect(locator).to_have_value(str(expected), timeout=timeout)
    except Exception as e:
        actual = _safe_input_value(locator)
        if not _values_match(actual, str(expected)):
            raise AssertionError(f"Assertion failed for 'bank_add_customer_email_textbox_email_field' expecting '{str(expected)}' but got '{actual}': {e}")


def enter_phone_number(page, value):
    page.smartAI('bank_add_customer_phone_number_textbox_phone_number_field').fill(str(value))

def assert_enter_phone_number(page, expected: str, timeout: int = 6000):
    locator = page.smartAI('bank_add_customer_phone_number_textbox_phone_number_field')
    try:
        expect(locator).to_have_value(str(expected), timeout=timeout)
    except Exception as e:
        actual = _safe_input_value(locator)
        if not _values_match(actual, str(expected)):
            raise AssertionError(f"Assertion failed for 'bank_add_customer_phone_number_textbox_phone_number_field' expecting '{str(expected)}' but got '{actual}': {e}")


def select_account_type(page, value):
    page.smartAI('bank_add_customer_account_type_select_account_type_select').select_option(value)

def enter_address(page, value):
    page.smartAI('bank_add_customer_address_textbox_address_field').fill(str(value))

def assert_enter_address(page, expected: str, timeout: int = 6000):
    locator = page.smartAI('bank_add_customer_address_textbox_address_field')
    try:
        expect(locator).to_have_value(str(expected), timeout=timeout)
    except Exception as e:
        actual = _safe_input_value(locator)
        if not _values_match(actual, str(expected)):
            raise AssertionError(f"Assertion failed for 'bank_add_customer_address_textbox_address_field' expecting '{str(expected)}' but got '{actual}': {e}")


def enter_occupation(page, value):
    page.smartAI('bank_add_customer_occupation_textbox_occupation_field').fill(str(value))

def assert_enter_occupation(page, expected: str, timeout: int = 6000):
    locator = page.smartAI('bank_add_customer_occupation_textbox_occupation_field')
    try:
        expect(locator).to_have_value(str(expected), timeout=timeout)
    except Exception as e:
        actual = _safe_input_value(locator)
        if not _values_match(actual, str(expected)):
            raise AssertionError(f"Assertion failed for 'bank_add_customer_occupation_textbox_occupation_field' expecting '{str(expected)}' but got '{actual}': {e}")


def enter_annual_income(page, value):
    page.smartAI('bank_add_customer_annual_income_textbox_annual_income_field').fill(str(value))

def assert_enter_annual_income(page, expected: str, timeout: int = 6000):
    locator = page.smartAI('bank_add_customer_annual_income_textbox_annual_income_field')
    try:
        expect(locator).to_have_value(str(expected), timeout=timeout)
    except Exception as e:
        actual = _safe_input_value(locator)
        if not _values_match(actual, str(expected)):
            raise AssertionError(f"Assertion failed for 'bank_add_customer_annual_income_textbox_annual_income_field' expecting '{str(expected)}' but got '{actual}': {e}")


def enter_initial_deposit(page, value):
    page.smartAI('bank_add_customer_initial_deposit_textbox_initial_deposit_field').fill(str(value))

def assert_enter_initial_deposit(page, expected: str, timeout: int = 6000):
    locator = page.smartAI('bank_add_customer_initial_deposit_textbox_initial_deposit_field')
    try:
        expect(locator).to_have_value(str(expected), timeout=timeout)
    except Exception as e:
        actual = _safe_input_value(locator)
        if not _values_match(actual, str(expected)):
            raise AssertionError(f"Assertion failed for 'bank_add_customer_initial_deposit_textbox_initial_deposit_field' expecting '{str(expected)}' but got '{actual}': {e}")


def click_cancel(page):
    page.smartAI('bank_add_customer_cancel_button_cancel_action').click()

def click_add_customer(page):
    page.smartAI('bank_add_customer_add_customer_button_add_customer_action').click()


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
    _step_prefixes = ('enter_', 'click_', 'select_', 'verify_', 'toggle_', 'hover_', 'upload_')
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
