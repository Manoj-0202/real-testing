You are a **Principal Application Security Architect** working on an
enterprise-grade AI-driven test automation platform.

Generate Playwright Python security tests for the user story below.

USER STORY
==========
Given I am on the CRM dashboard on https://bank-buddy-crm-react.lovable.app/
When I click the "Customers" tab,
And I click the "Add Customer" button,
And I enter "John Doe" in the Full Name field,
And I enter "john.doe@example.com" in the Email field,
And I enter "1234567890" in the Phone Number field,
And I select "Standard" for Account Type,
And I enter "123 Main St, Anytown, USA" in the Address field,
And I enter "Software Engineer" in the Occupation field,
And I enter "75000" in the Annual Income field,
And I enter "1000" in the Initial Deposit field,
And I click the "Add Customer" button,
Then the customer should be added successfully.

AVAILABLE PAGE METHODS
======================
# bank_add_customer:
- def _ci(s):  # case-insensitive canonical
- def _digits_only(s):
- def _values_match(actual, expected):
- def _safe_input_value(locator):
- def enter_full_name(page, value):
- def assert_enter_full_name(page, expected: str, timeout: int = 6000):
- def enter_email(page, value):
- def assert_enter_email(page, expected: str, timeout: int = 6000):
- def enter_phone_number(page, value):
- def assert_enter_phone_number(page, expected: str, timeout: int = 6000):
- def select_account_type(page, value):
- def enter_address(page, value):
- def assert_enter_address(page, expected: str, timeout: int = 6000):
- def enter_occupation(page, value):
- def assert_enter_occupation(page, expected: str, timeout: int = 6000):
- def enter_annual_income(page, value):
- def assert_enter_annual_income(page, expected: str, timeout: int = 6000):
- def enter_initial_deposit(page, value):
- def assert_enter_initial_deposit(page, expected: str, timeout: int = 6000):
- def click_cancel(page):
- def click_add_customer(page):
# bank_customer:
- def _ci(s):  # case-insensitive canonical
- def _digits_only(s):
- def _values_match(actual, expected):
- def _safe_input_value(locator):
- def enter_search_customers_loans_transactions(page, value):
- def assert_enter_search_customers_loans_transactions(page, expected: str, timeout: int = 6000):
- def verify_bank_crm_visible(page):
- def click_dashboard(page):
- def click_customers(page):
- def click_loans(page):
- def click_transactions(page):
- def click_tasks(page):
- def click_reports(page):
- def click_analytics(page):
- def click_settings(page):
- def enter_search_customers(page, value):
- def assert_enter_search_customers(page, expected: str, timeout: int = 6000):
- def click_export(page):
- def click_add_new_customer(page):
- def click_filters(page):
- def click_edit_with_lovable(page):
# bank_dashboard:
- def _ci(s):  # case-insensitive canonical
- def _digits_only(s):
- def _values_match(actual, expected):
- def _safe_input_value(locator):
- def verify_bank_crm_visible(page):
- def enter_search_customers_loans_transactions(page, value):
- def assert_enter_search_customers_loans_transactions(page, expected: str, timeout: int = 6000):
- def click_dashboard(page):
- def click_customers(page):
- def click_loans(page):
- def click_transactions(page):
- def click_tasks(page):
- def click_reports(page):
- def click_analytics(page):
- def click_settings(page):
- def click_export_report(page):
- def click_john_doe(page):

INPUT METHODS ELIGIBLE FOR PAYLOAD INJECTION
============================================
- _safe_input_value(page, <payload>)
- _values_match(page, <payload>)
- assert_enter_address(page, <payload>)
- assert_enter_email(page, <payload>)
- assert_enter_full_name(page, <payload>)
- assert_enter_phone_number(page, <payload>)
- enter_address(page, <payload>)
- enter_annual_income(page, <payload>)
- enter_email(page, <payload>)
- enter_full_name(page, <payload>)
- enter_initial_deposit(page, <payload>)
- enter_occupation(page, <payload>)
- enter_phone_number(page, <payload>)
- enter_search_customers(page, <payload>)
- enter_search_customers_loans_transactions(page, <payload>)
- select_account_type(page, <payload>)

LOGIN / SUBMIT ACTIONS
======================
If a POM method exists to submit the form or click the login button, CALL IT using the exact method name.
Try the following common candidate names (in order) if present in the POMs:
    click_login
    click_login_button
    click_login_submit
    submit_login
    press_login
    click_sign_in
If none of these methods are present, add a skipped-step comment INSIDE the test body:
    # Skipped submit due to missing method: <reason>

RULES
=====
1. USE ONLY the POM methods listed above.
2. Pass `page` as the first argument to every POM method call.
3. NO imports, no helper functions, no locators.
4. Each test MUST start with:
    page.goto("")
5. Output ONLY executable Python test functions.

REQUIRED TEST FUNCTIONS
=======================

1) XSS
Function: test_security_xss(page)
- Inject payloads into every input:
    "<script>alert('XSS')</script>"
    '"><img src=x onerror=alert("XSS")>'
    "<svg/onload=alert(1)>"
    "<iframe src=javascript:alert(1)>"
- Register dialogs and assert none fired:
    dialogs = []
    page.on("dialog", lambda d: dialogs.append(d.message))
    assert not dialogs

2) SQLi
Function: test_security_sqli(page)
- Inject payloads:
    "' OR '1'='1"
    "' OR '1'='1' --"
    "' UNION SELECT NULL,NULL --"
    "'; DROP TABLE users; --"
- Assert page content has no SQL error keywords.

3) Command Injection
Function: test_security_command_injection(page)
- Inject payloads:
    "; ls"
    "&& whoami"
    "| cat /etc/passwd"
    "$(whoami)"
    "`whoami`"
- Assert app remains stable (page.url or page.title not empty).

4) Input Fuzzing
Function: test_security_input_fuzzing(page)
- Inject payloads:
    "A" * 5000
    "B" * 10000
    "@#$%^&*()" * 200
    "9" * 100
- Assert page still responds.

5) Security Headers
Function: test_security_headers(page)
- response = page.goto("")
- headers = response.headers or {}
- Assert:
    "content-security-policy"
    "x-frame-options"
    "x-content-type-options"
    "strict-transport-security" (only if https)

OUTPUT ONLY the five test functions. No markdown, no extra text.
