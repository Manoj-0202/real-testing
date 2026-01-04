You are a **Senior Automation Architect**. Generate **Playwright Python test scripts** for the following user story:

USER STORY:
"""Given I am on the CRM dashboard on https://bank-buddy-crm-react.lovable.app/
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
Then the customer should be added successfully."""


===========================================
🚨 ABSOLUTE RULES (MUST FOLLOW)
===========================================

1. **USE ONLY the POM methods listed below.**
   - NEVER create or guess new method names.
   - NEVER write locators: no page.locator(), no CSS, no XPath.
   - ONLY call existing POM functions: def method(page, ...).

2. **DO NOT write import statements.**
   The runner auto-handles imports.

3. **DO NOT create helper functions.**
   Only write test functions.

4. **EVERY test MUST start with:**
    page.goto("")

5.1 **Never use empty strings for inputs.**
    If the user story provides a value, use it exactly.

5.2 **Map steps to the closest available POM method.**
    If a step mentions a field/button and there is a matching `enter_`/`select_`/`click_` method in the list,
    use it instead of skipping.

6. **Output ONLY valid Python code — no markdown, no comments outside the test body.**


===========================================
📌 REQUIRED TEST FUNCTIONS
===========================================

You MUST generate the following test functions:

-----------------------------------------------------------
1️⃣ **POSITIVE TEST**
Function name:
    test_positive_feature()

Rules:
– Follow the correct flow exactly as per the user story  
– Use valid inputs  
– Use POM methods in correct order  
– Use assert_* POM methods wherever available  

-----------------------------------------------------------
2️⃣ **NEGATIVE TEST**
Function name:
    test_negative_feature()

Rules:
– Use invalid/missing inputs  
– Example: empty strings, wrong formats  
– Should lead to failure paths  
– Use assert_* methods where applicable  

-----------------------------------------------------------
3️⃣ **EDGE TEST**
Function name:
    test_edge_feature()

Rules:
– Use extreme inputs:
    "A" * 256
    "!@#$%^&*()"
    very long email
– Still follow user story steps  
– Use POM methods only  

-----------------------------------------------------------
4️⃣ **ACCESSIBILITY TEST**
Function name:
    test_accessibility_feature()

Rules:
– Follow positive flow navigation using ONLY POM methods  
– At logical checkpoints validate accessibility using Playwright:

        expect(page.get_by_text("Full Name")).to_be_visible()

– DO NOT create or use accessibility helper methods  
– DO NOT use Axe directly (your framework triggers it automatically)  

-----------------------------------------------------------
5️⃣ **SECURITY TESTS**

You MUST generate the following security test functions:

**A) XSS (Cross-Site Scripting) TEST**
Function name:
    test_security_xss()

Rules:
– Inject XSS payloads into **every input POM method**.
      Payload 1: "<script>alert('XSS')</script>"
      Payload 2: '"><img src=x onerror=alert("XSS")>'
– Use a different payload for each input field if possible.
– After submitting, assert that the script was not executed or rendered:
      assert "<script>" not in page.content()
– Use only POM methods for navigation & input.

**B) SQL Injection (SQLi) TEST**
Function name:
    test_security_sqli()

Rules:
– Inject SQLi payloads into **every input POM method**.
      Payload 1: "' OR '1'='1"
      Payload 2: "' OR '1'='1' --"
– Use a different payload for each input field if possible.
– After submitting, check for generic error pages or unexpected success.
– Use only POM methods for navigation & input.

**C) SECURITY HEADERS TEST**
Function name:
    test_security_headers()

Rules:
– Navigate to the site's main URL.
– Verify that essential security headers are present.
    response = page.goto("")
    headers = response.headers or {}
    assert any(k.lower() == "content-security-policy" for k in headers)
    assert any(k.lower() == "x-frame-options" for k in headers)  


===========================================
📄 PAGE OBJECT METHODS (ALLOWED)
===========================================
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


===========================================
💡 EXTRA HINTS
===========================================
    - Call `enter_full_name("<full_name>")`
    - Call `enter_email("<email>")`
    - Call `enter_phone_number("<phone_number>")`
    - Call `select_account_type("<value>")`
    - Call `enter_address("<address>")`
    - Call `enter_occupation("<occupation>")`
    - Call `enter_annual_income("<annual_income>")`
    - Call `enter_initial_deposit("<initial_deposit>")`
    - Call `click_cancel()`
    - Call `click_add_customer()`
    - Call `enter_search_customers_loans_transactions("<search_customers_loans_transactions>")`
    - Assert `verify_bank_crm_visible()` checks if **Bank crm visible** is visible
    - Call `click_dashboard()`
    - Call `click_customers()`
    - Call `click_loans()`
    - Call `click_transactions()`
    - Call `click_tasks()`
    - Call `click_reports()`
    - Call `click_analytics()`
    - Call `click_settings()`
    - Call `enter_search_customers("<search_customers>")`
    - Call `click_export()`
    - Call `click_add_new_customer()`
    - Call `click_filters()`
    - Call `click_edit_with_lovable()`
    - Assert `verify_bank_crm_visible()` checks if **Bank crm visible** is visible
    - Call `enter_search_customers_loans_transactions("<search_customers_loans_transactions>")`
    - Call `click_dashboard()`
    - Call `click_customers()`
    - Call `click_loans()`
    - Call `click_transactions()`
    - Call `click_tasks()`
    - Call `click_reports()`
    - Call `click_analytics()`
    - Call `click_settings()`
    - Call `click_export_report()`
    - Call `click_john_doe()`


===========================================
🎯 OUTPUT FORMAT — CRITICAL
===========================================

Output ONLY valid Python test functions:

❌ No imports  
❌ No markdown  
❌ No helper functions  
❌ No text outside the tests  

Each test MUST follow:

def test_positive_feature(page):
    page.goto("SITE_URL")
    <POM method calls>
    <assertions>

NOW GENERATE ALL FIVE TEST FUNCTIONS.
