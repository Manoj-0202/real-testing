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


def verify_bank_crm_visible(page):
    expect(page.smartAI('bank_dashboard_bank_crm_label_bank_crm_info')).to_be_visible()

def enter_search_customers_loans_transactions(page, value):
    page.smartAI('bank_dashboard_search_customers_loans_transactions_textbox_search_customers_loans_transactions_field').fill(str(value))

def assert_enter_search_customers_loans_transactions(page, expected: str, timeout: int = 6000):
    locator = page.smartAI('bank_dashboard_search_customers_loans_transactions_textbox_search_customers_loans_transactions_field')
    try:
        expect(locator).to_have_value(str(expected), timeout=timeout)
    except Exception as e:
        actual = _safe_input_value(locator)
        if not _values_match(actual, str(expected)):
            raise AssertionError(f"Assertion failed for 'bank_dashboard_search_customers_loans_transactions_textbox_search_customers_loans_transactions_field' expecting '{str(expected)}' but got '{actual}': {e}")


def click_dashboard(page):
    page.smartAI('bank_dashboard_dashboard_link_dashboard_action').click()

def click_customers(page):
    page.smartAI('bank_dashboard_customers_link_customers_action').click()

def click_loans(page):
    page.smartAI('bank_dashboard_loans_link_loans_action').click()

def click_transactions(page):
    page.smartAI('bank_dashboard_transactions_link_transactions_action').click()

def click_tasks(page):
    page.smartAI('bank_dashboard_tasks_link_tasks_action').click()

def click_reports(page):
    page.smartAI('bank_dashboard_reports_link_reports_action').click()

def click_analytics(page):
    page.smartAI('bank_dashboard_analytics_link_analytics_action').click()

def click_settings(page):
    page.smartAI('bank_dashboard_settings_link_settings_action').click()

def click_export_report(page):
    page.smartAI('bank_dashboard_export_report_button_export_report_action').click()

def click_john_doe(page):
    page.smartAI('bank_dashboard_john_doe_link_john_doe_action').click()


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
