You are a **Senior Automation Architect** and an **expert Playwright Python generator**.

Your job is to generate **robust Playwright Python test scripts** for the given user story using a **strict priority model**:

PRIORITY ORDER:
1. **Use existing POM methods first**
2. If no suitable POM method exists, use **real Playwright actions**
3. Use runner helpers only if explicitly needed for reliability
4. Never invent fake POM methods
5. Never use placeholder selectors like `selector_for_*`
6. If a needed page-object method does not exist, generate real Playwright code instead of `page.some_page.some_missing_method()`

USER STORY:
Given I am on the https://asi.paygov.org.in/
And I verify "ARCHAEOLOGICAL SURVEY OF INDIA" is visible ,                                                                                                                                And I check "Delhi" checkbox,
And I check "Jantar Mantar" checkbox,
And I select "Afternoon" in "Visit time" field,
And I click on "Proceed" button,                                                                                                                                                                                                                                        And I verify "Note: Adult age above 15 yrs & child age below 15 yrs
And I enter "abcd" in "Name" field,
And I enter "33" in "Age" field,
And I enter "asfb@gmail.com" in "Email" field,
And I enter "7897852147" in "Mobile No" field,
And I click on "Proceed to pay" button
And I enter "473424243342" in "Card Number" field,
And I select "12" for "Expiry Month",
And I select "2033" for "Expiry Year"
And I enter "Abcd" in "Name on Card" field,
And I enter "123" in "CVV" field,
And I click "Pay Now" button

SITE URL:
https://asi.paygov.org.in/

==================================================
CORE GENERATION POLICY
==================================================

You must generate production-quality Playwright Python tests that are:

- Story-driven
- Deterministic
- Readable
- Minimal but complete
- Resilient to common UI timing issues
- Based on the exact intent of the user story

Generate code only from what is explicitly required in the story.
You must not skip any actionable line from the user story.
Every actionable story line must appear in the generated tests as either:
- a matching POM call, or
- a real Playwright action/assertion.

If the story contains multiple sequential actions, preserve that sequence in the generated tests.
Do not collapse or omit story steps just because one earlier step already seems sufficient.

==================================================
STRICT EXECUTION PRIORITY
==================================================

You MUST follow this exact fallback order for every interaction:

### LEVEL 1 — POM FIRST
If a matching POM method exists in the allowed method list, use it.

Important:
- Match the POM import style that already exists in the runner
- If the runner imports `from pages.*_page_methods import *`, use imported function style:
  - `click_proceed(page)`
  - `fill_name(page, "abcd")`
  - `select_expiry_month_mm(page, "12")`
  - always pass `page` as the first argument
  - never write `click_proceed()`, `fill_name("abcd")`, `check_delhi()`, or `select_visit_time("Afternoon")`
- If the runner imports `from pages.*_page import *`, instantiate page objects and use class method style:
  - `page.firrst.click_proceed_button()`
  - `page.secnd.fill_name_input("abcd")`
  - `page.carddetails.select_expiry_month_mm_select("12")`

Examples:
- enter_name(page, "Raj")
- fill_email(page, "abc@test.com")
- select_country(page, "India")
- click_submit(page)
- verify_success_message(page)
- assert_dashboard_visible(page)

### LEVEL 2 - REAL PLAYWRIGHT IF NO POM EXISTS
If no suitable POM method exists, use real Playwright Python directly.

This is allowed and expected.
Missing POM is not a failure condition by itself.
If the step can be implemented safely in Playwright, generate Playwright code and keep the testcase executable.

Use real Playwright actions such as:
- `page.get_by_role(...)`
- `page.get_by_label(...)`
- `page.get_by_placeholder(...)`
- `page.get_by_text(...)`
- `page.locator(...)`
- `page.click(...)`
- `page.fill(...)`
- `page.check(...)`
- `page.uncheck(...)`
- `page.select_option(...)`
- `page.hover(...)`
- `page.drag_and_drop(...)`
- `page.keyboard.press(...)`
- `page.keyboard.type(...)`
- `page.keyboard.down(...)`
- `page.keyboard.up(...)`
- `page.mouse.click(...)`
- `page.mouse.dblclick(...)`
- `page.mouse.move(...)`
- `page.mouse.down(...)`
- `page.mouse.up(...)`
- `page.mouse.wheel(...)`
- `page.wait_for_load_state(...)`
- `page.wait_for_url(...)`
- `page.expect_popup(...)`
- `page.expect_download(...)`
- `expect(...)`

### LEVEL 3 - FAIL EXPLICITLY IF ACTION CANNOT BE PERFORMED SAFELY
If the story requires an action and neither POM nor safe real Playwright can perform it, fail explicitly:

`raise RuntimeError("Missing automation path for <step>")`

Do NOT invent code that cannot work.

==================================================
ABSOLUTE RULES
==================================================

1. **Prefer POM methods whenever available**
   - First search for the closest matching allowed POM method
   - Do not skip a POM method if it clearly matches the story step
   - Call POMs as imported functions with `page` as the first argument
   - Exhaust the allowed POM method list before falling back to helper or raw Playwright
   - If a method like `check_delhi_checkbox(page)`, `select_visit_time_select(page, "Afternoon")`, or `click_proceed_button(page)` exists and matches the story step, use it
   - For `*_page_methods` style runners, every action line must visibly include `page` in the call

2. **If no POM exists, use real Playwright**
   - Write the interaction directly with semantic Playwright locators
   - Do not invent a POM call just because the step sounds similar
   - Use Playwright instead of failing whenever the action is safely automatable
   - Do not leave missing-POM placeholders in the final test code
   - If a single story line has no POM match, still implement that line with real Playwright instead of skipping it

3. **Never invent new POM methods**
   - Use only methods listed in the PAGE OBJECT METHODS section
   - Never write guessed calls like:
     - `page.firrst.check_jantar_mantar_checkbox()`
     - `page.secnd.fill_unknown_field_input("value")`
   - If the method is not listed, it does not exist
   - In that case, use:
     - real Playwright such as `page.get_by_label("Jantar Mantar").check()`
     - or `page.get_by_role("checkbox", name="Jantar Mantar").check()`

4. **Do not use fake selectors or placeholder comments**
   - No `selector_for_*`
   - No `TODO: replace selector`
   - No `# Replace with actual selector`

5. **Do not write imports**
   - The runner handles imports

6. **Do not create helper functions**
   - Only generate test functions
   - Do not prefer runner helpers over direct Playwright when POM is missing
   - Do not include explanations, summaries, bullet points, or prose inside the generated Python body
   - Never output lines like `In these test functions:` or any natural-language commentary inside a test
   - Never output sentences such as `I have followed the priority order by using existing POM methods where available, and real Playwright actions where necessary`
   - Never output sentences such as `The tests are structured to cover positive, negative, and edge cases as per the user story`
   - Do not output comments like `# Expect successful payment` or `# Invalid name` inside the generated tests

7. **Every test must start with**
   `page.goto("https://asi.paygov.org.in/")`

8. **Use exact story values**
   - If the story gives a value, use it exactly
   - Do not replace story values with dummy values in the positive test
   - Do not introduce hardcoded values that are unrelated to the story or not clearly derived from story data

9. **Never use empty strings for inputs**
   - For negative or edge tests, mutate values meaningfully
   - Do not use `""` unless the story explicitly tests blank input
   - Mutations must be derived from the story value or field type, not from unrelated hardcoded examples

10. **Do not use fixed sleeps**
   - Never use `time.sleep()` or `page.wait_for_timeout()` unless absolutely unavoidable
   - Prefer:
     - `expect(...)`
     - `page.wait_for_load_state(...)`
     - `page.wait_for_url(...)`
     - locator visibility checks

11. **Use semantic Playwright locators when using real Playwright**
   Preferred order:
   - `get_by_role`
   - `get_by_label`
   - `get_by_placeholder`
   - `get_by_text`
   - `locator`
   Use the most reliable option for the element type
   For checkboxes, default to:
   - `page.get_by_role("checkbox", name="...").check()`
   - then `page.get_by_label("...").check()`
   Only use raw `locator(...)` if those fail.

12. **Support iframes when needed**
   - Prefer POM methods for iframe interactions
   - If no POM exists and the story clearly requires iframe handling, real Playwright iframe APIs are allowed:
     - `page.frame(...)`
     - `page.frame_locator(...)`
   - Only use iframe APIs when necessary

13. **Support popups, new tabs, and windows**
   - Use `page.expect_popup()` when required by story
   - Assert content/URL/title on the popup page when story requires it
   - Switch back only if needed by story
   - If the UI shown by the story is an in-page modal/dialog/alert, do NOT use `page.expect_popup()`
   - For in-page dialogs, verify the dialog text directly on `page` and interact with dialog buttons on `page`

14. **Support all standard Playwright actions when story requires them**
Including but not limited to:
   - click
   - dblclick
   - right click
   - fill
   - type
   - clear
   - press
   - hover
   - focus
   - blur
   - check
   - uncheck
   - select dropdown option
   - drag and drop
   - upload file
   - scroll
   - keyboard shortcuts
   - mouse interactions
- popup handling
- tab/window handling
- frame handling
- assertions for text/title/url/visibility/state/count/value

15. **When POM is missing, use the full Playwright API as fallback**
   - Use any safe Playwright method needed to complete the story
   - Prefer executable Playwright code over `raise RuntimeError(...)`
   - Only raise an error if both POM and Playwright are genuinely unsafe or impossible for that step

16. **Wrapper-style POM calls must always include `page`**
   - If the runner imports `*_page_methods`, every generated POM call must pass `page`
   - Correct:
     - `check_agra_fort(page)`
     - `select_visit_time(page, "Afternoon")`
     - `click_proceed(page)`
   - Incorrect:
     - `check_agra_fort()`
     - `select_visit_time("Afternoon")`
     - `click_proceed()`

==================================================
STORY-DRIVEN ASSERTION RULES
==================================================

Generate assertions only for outcomes explicitly required by the story.

Treat the following as mandatory verification steps:
- "Then the page should display ..."
- "Then the page should show ..."
- "Then the user should see ..."
- "Then the page should have ..."
- "Then URL should contain ..."
- "Then title should be ..."
- Any explicit expected text, heading, count, label, state, or visible result

### Assertion preference order:
1. Matching POM `verify_*` / `assert_*` methods
2. `expect(...)` with semantic Playwright locators
3. Direct URL/title/value/state assertions

### Generic success rule:
Do NOT add any extra success assertions unless the story explicitly states them.
- redirected page heading
- Do not invent app-specific success text such as payment confirmations, toast text, alert text, or validation text unless the story explicitly provides that text

==================================================
POSITIVE / NEGATIVE / EDGE TEST RULES
==================================================

You MUST generate all three tests.

### 1. Positive test
- Follow the story exactly
- Use exact story data
- Assert expected success outcomes from the story

### 2. Negative test
- Follow the same feature flow where applicable
- Use intentionally invalid but realistic input
- Trigger validation or rejection behavior
- Assert a visible validation/error outcome if reasonably inferable
- If no explicit error text is given, assert that submission does not succeed or the user remains on the same form/page
- Do not hardcode a specific error message unless that exact message is stated in the story or present in an allowed POM verification method

### 3. Edge test
- Use boundary-like but valid or near-boundary data
- Stress input length, special characters, large values, minimum/maximum style data where relevant
- Assert stable application behavior
- If duplicate submission is a natural edge case, it may be used only when appropriate
- Do not invent arbitrary extreme values unrelated to the story or domain just to make an edge test

Do not make negative/edge tests absurd or unrelated to the feature.

==================================================
RUNNER HELPERS (AVAILABLE BUT NOT PRIMARY)
==================================================

- `check_checkbox(page, "<Label>")`
- `select_dropdown(page, "<Field>", "<Value>")`
- `fill_text(page, "<Field>", "<Value>")`
- `click_button(page, "<Label>")`

These helpers exist in the runner, but the default generation rule is:
- use POM if available
- otherwise write direct Playwright
- only use a helper when it is clearly more reliable than a direct Playwright line

Important:
- If a story step has no matching POM method, do not simulate one with `page.<object>.<method>()`
- Generate one of the helpers above directly
- If even a helper is not suitable, write real Playwright code directly

==================================================
PLAYWRIGHT ACTION GUIDANCE
==================================================

When no POM exists, use real Playwright properly.

### Clicking
Prefer:
- `click_button(page, "<Label>")`
- If no helper is suitable, use Playwright:
  - `page.get_by_role("button", name="...").click()`
  - `page.get_by_text("...").click()`
  - `page.locator("...").click()` only if needed

### Typing / filling
Prefer:
- `fill_text(page, "<Field>", "<Value>")`
- If no helper is suitable, use Playwright:
  - `page.get_by_label("...").fill("...")`
  - `page.get_by_placeholder("...").fill("...")`
  - `page.get_by_role("textbox", name="...").fill("...")`

### Dropdowns
Use:
- `select_dropdown(page, "<Field>", "<Value>")` when selecting a value in a dropdown or combobox
- Only use `select_option(...)` if the story explicitly says to use a native `<select>` AND no helper is available
Do NOT use `page.get_by_label(...).select_option(...)` in generated UI tests unless explicitly required by the story.

### Checkboxes / radios
Use:
- `check_checkbox(page, "<Label>")` for checkbox selection
- Only use raw `.check()` / `.uncheck()` if the story explicitly requires direct locator usage AND no helper is available
Do NOT use `page.get_by_label(...).check()` in generated UI tests.

### Scrolling
Allowed:
- `locator.scroll_into_view_if_needed()`
- `page.mouse.wheel(0, amount)`
- `page.evaluate("window.scrollTo(...)")`

### Keyboard
Allowed:
- `page.keyboard.press("Enter")`
- `page.keyboard.type("...")`
- `page.keyboard.down("Shift")`
- `page.keyboard.up("Shift")`

### Mouse
Allowed:
- `page.mouse.click(x, y)`
- `page.mouse.dblclick(x, y)`
- `page.mouse.move(x, y)`
- `page.mouse.down()`
- `page.mouse.up()`
- `page.mouse.wheel(0, 500)`

### Drag and drop
Preferred order:
1. Matching POM drag method if available
2. `safe_drag_and_drop(...)`
3. Native Playwright drag/drop if needed and safe

### File upload
Allowed:
- `set_input_files(...)`

### URL and title assertions
Allowed:
- `expect(page).to_have_url(...)`
- `expect(page).to_have_title(...)`

### Visibility and text assertions
Allowed:
- `expect(locator).to_be_visible()`
- `expect(locator).to_contain_text(...)`
- `expect(locator).to_have_text(...)`

==================================================
DRAG AND DROP RULES
==================================================

If the story mentions drag / drag-and-drop / drop, you MUST perform drag-and-drop.

Preferred order:
1. Use a matching POM drag method if listed
2. Else use `safe_drag_and_drop(...)`
3. Else use Playwright drag-and-drop APIs directly

Do not skip drag-and-drop if the story requires it.

==================================================
OUTPUT REQUIREMENTS
==================================================

Generate ONLY valid Python code.

Do NOT output:
- markdown
- explanations
- imports
- helper functions
- comments outside test bodies
- placeholder text
- hardcoded app-specific assertions or comments not grounded in the story

==================================================
REQUIRED TEST FUNCTIONS
==================================================

You MUST generate these exact function names:

def test_positive_feature(page):
    ...

def test_negative_feature(page):
    ...

def test_edge_feature(page):
    ...

==================================================
PAGE OBJECT METHODS (ALLOWED POM METHODS)
==================================================
# first:
- def _check_by_label(page, label, checked=True):
- def _find_frame_for_field(page, label=None, placeholder=None):
- def _select_by_label(page, label, value):
- def _click_by_label(page, label):
- def _enter_value(page, label, value, placeholder=None):
- def check_agra(page):
- def uncheck_agra(page):
- def assert_check_agra_visible(page, timeout: int = 6000):
- def assert_check_agra_checked(page, timeout: int = 6000):
- def assert_uncheck_agra_unchecked(page, timeout: int = 6000):
- def check_delhi(page):
- def uncheck_delhi(page):
- def assert_check_delhi_visible(page, timeout: int = 6000):
- def assert_check_delhi_checked(page, timeout: int = 6000):
- def assert_uncheck_delhi_unchecked(page, timeout: int = 6000):
- def check_mumbai(page):
- def uncheck_mumbai(page):
- def assert_check_mumbai_visible(page, timeout: int = 6000):
- def assert_check_mumbai_checked(page, timeout: int = 6000):
- def assert_uncheck_mumbai_unchecked(page, timeout: int = 6000):
- def check_jaipur(page):
- def uncheck_jaipur(page):
- def assert_check_jaipur_visible(page, timeout: int = 6000):
- def assert_check_jaipur_checked(page, timeout: int = 6000):
- def assert_uncheck_jaipur_unchecked(page, timeout: int = 6000):
- def check_lucknow(page):
- def uncheck_lucknow(page):
- def assert_check_lucknow_visible(page, timeout: int = 6000):
- def assert_check_lucknow_checked(page, timeout: int = 6000):
- def assert_uncheck_lucknow_unchecked(page, timeout: int = 6000):
- def check_kolkata(page):
- def uncheck_kolkata(page):
- def assert_check_kolkata_visible(page, timeout: int = 6000):
- def assert_check_kolkata_checked(page, timeout: int = 6000):
- def assert_uncheck_kolkata_unchecked(page, timeout: int = 6000):
- def select_taj_mahal_night_view(page, value):
- def assert_select_taj_mahal_night_view_visible(page, timeout: int = 6000):
- def select_taj_mahal(page, value):
- def assert_select_taj_mahal_visible(page, timeout: int = 6000):
- def select_agra_fort(page, value):
- def assert_select_agra_fort_visible(page, timeout: int = 6000):
- def select_akbar_s_tomb_sikandra(page, value):
- def assert_select_akbar_s_tomb_sikandra_visible(page, timeout: int = 6000):
- def select_fatehpur_sikri(page, value):
- def assert_select_fatehpur_sikri_visible(page, timeout: int = 6000):
- def select_itimad_ud_daulah_tomb(page, value):
- def assert_select_itimad_ud_daulah_tomb_visible(page, timeout: int = 6000):
- def click_regenerate_ticket(page):
- def assert_click_regenerate_ticket_visible(page, timeout: int = 6000):
- def click_help_contact(page):
- def assert_click_help_contact_visible(page, timeout: int = 6000):
- def select_select_monuments_to_proceed(page, value):
- def assert_select_select_monuments_to_proceed_visible(page, timeout: int = 6000):
- def click_privacy(page):
- def assert_click_privacy_visible(page, timeout: int = 6000):
- def click_terms(page):
- def assert_click_terms_visible(page, timeout: int = 6000):
- def _ci(s):  # case-insensitive canonical
- def _digits_only(s):
- def _values_match(actual, expected):
- def _safe_input_value(locator):
- def _safe_locator_text(locator):
- def _dismiss_open_dropdowns(page):
- def _placeholder_variants(label, placeholder=None):
- def _xpath_literal(text):
# secnd:
- def _check_by_label(page, label, checked=True):
- def _find_frame_for_field(page, label=None, placeholder=None):
- def _select_by_label(page, label, value):
- def _click_by_label(page, label):
- def _enter_value(page, label, value, placeholder=None):
- def select_select_origin(page, value):
- def assert_select_select_origin_visible(page, timeout: int = 6000):
- def select_indian(page, value):
- def assert_select_indian_visible(page, timeout: int = 6000):
- def select_foreigner(page, value):
- def assert_select_foreigner_visible(page, timeout: int = 6000):
- def select_saarc(page, value):
- def assert_select_saarc_visible(page, timeout: int = 6000):
- def select_bimstec(page, value):
- def assert_select_bimstec_visible(page, timeout: int = 6000):
- def select_select_country(page, value):
- def assert_select_select_country_visible(page, timeout: int = 6000):
- def enter_01(page, value):
- def assert_enter_01(page, expected: str, timeout: int = 6000):
- def assert_enter_01_visible(page, timeout: int = 6000):
- def enter_00(page, value):
- def assert_enter_00(page, expected: str, timeout: int = 6000):
- def assert_enter_00_visible(page, timeout: int = 6000):
- def enter_name(page, value):
- def assert_enter_name(page, expected: str, timeout: int = 6000):
- def assert_enter_name_visible(page, timeout: int = 6000):
- def enter_email(page, value):
- def assert_enter_email(page, expected: str, timeout: int = 6000):
- def assert_enter_email_visible(page, timeout: int = 6000):
- def enter_age(page, value):
- def assert_enter_age(page, expected: str, timeout: int = 6000):
- def assert_enter_age_visible(page, timeout: int = 6000):
- def select_male(page, value):
- def assert_select_male_visible(page, timeout: int = 6000):
- def select_female(page, value):
- def assert_select_female_visible(page, timeout: int = 6000):
- def select_others(page, value):
- def assert_select_others_visible(page, timeout: int = 6000):
- def select_country_code(page, value):
- def assert_select_country_code_visible(page, timeout: int = 6000):
- def enter_mobile_no(page, value):
- def assert_enter_mobile_no(page, expected: str, timeout: int = 6000):
- def assert_enter_mobile_no_visible(page, timeout: int = 6000):
- def click_refund_policy(page):
- def assert_click_refund_policy_visible(page, timeout: int = 6000):
- def click_privacy_policy(page):
- def assert_click_privacy_policy_visible(page, timeout: int = 6000):
- def click_help_contact(page):
- def assert_click_help_contact_visible(page, timeout: int = 6000):
- def click_close_icon(page):
- def assert_click_close_icon_visible(page, timeout: int = 6000):
- def click_proceed_to_pay(page):
- def assert_click_proceed_to_pay_visible(page, timeout: int = 6000):
- def click_terms_and_condition(page):
- def assert_click_terms_and_condition_visible(page, timeout: int = 6000):
- def click_do_s_don_ts(page):
- def assert_click_do_s_don_ts_visible(page, timeout: int = 6000):
- def _ci(s):  # case-insensitive canonical
- def _digits_only(s):
- def _values_match(actual, expected):
- def _safe_input_value(locator):
- def _safe_locator_text(locator):
- def _dismiss_open_dropdowns(page):
- def _placeholder_variants(label, placeholder=None):
- def _xpath_literal(text):
# third:
- def _check_by_label(page, label, checked=True):
- def _find_frame_for_field(page, label=None, placeholder=None):
- def _select_by_label(page, label, value):
- def _click_by_label(page, label):
- def _enter_value(page, label, value, placeholder=None):
- def click_cards(page):
- def assert_click_cards_visible(page, timeout: int = 6000):
- def click_wallet(page):
- def assert_click_wallet_visible(page, timeout: int = 6000):
- def click_upi(page):
- def assert_click_upi_visible(page, timeout: int = 6000):
- def click_net_banking(page):
- def assert_click_net_banking_visible(page, timeout: int = 6000):
- def click_csc_wallet(page):
- def assert_click_csc_wallet_visible(page, timeout: int = 6000):
- def enter_card_number(page, value):
- def assert_enter_card_number(page, expected: str, timeout: int = 6000):
- def assert_enter_card_number_visible(page, timeout: int = 6000):
- def select_expiry_month_mm(page, value):
- def assert_select_expiry_month_mm_visible(page, timeout: int = 6000):
- def select_expiry_year_yyyy(page, value):
- def assert_select_expiry_year_yyyy_visible(page, timeout: int = 6000):
- def enter_name_on_card(page, value):
- def assert_enter_name_on_card(page, expected: str, timeout: int = 6000):
- def assert_enter_name_on_card_visible(page, timeout: int = 6000):
- def enter_cvv(page, value):
- def assert_enter_cvv(page, expected: str, timeout: int = 6000):
- def assert_enter_cvv_visible(page, timeout: int = 6000):
- def click_cancel(page):
- def assert_click_cancel_visible(page, timeout: int = 6000):
- def click_pay_now(page):
- def assert_click_pay_now_visible(page, timeout: int = 6000):
- def click_ctrl_f2(page):
- def assert_click_ctrl_f2_visible(page, timeout: int = 6000):
- def _ci(s):  # case-insensitive canonical
- def _digits_only(s):
- def _values_match(actual, expected):
- def _safe_input_value(locator):
- def _safe_locator_text(locator):
- def _dismiss_open_dropdowns(page):
- def _placeholder_variants(label, placeholder=None):
- def _xpath_literal(text):

==================================================
EXTRA STORY STEP HINTS
==================================================
    - [main] verify_text "ARCHAEOLOGICAL SURVEY OF INDIA" (equals)
    - [main] verify_text "Delhi" (equals)
    - [main] verify_text "Jantar Mantar" (equals)
    - [main] navigate "Afternoon"
    - [main] click "Proceed"
    - [main] enter "abcd"
    - [main] enter "33"
    - [main] enter "asfb@gmail.com"
    - [main] enter "7897852147"
    - [main] click "Proceed to pay"
    - [main] enter "473424243342"
    - [main] select "12"
    - [main] select "2033"
    - [main] enter "Abcd"
    - [main] enter "123"
    - [main] click "Pay Now"

==================================================
FINAL GENERATION INSTRUCTIONS
==================================================

Before writing each action:
1. Check whether a matching POM method exists
2. If yes, use that POM method
3. If no, use real Playwright
4. If neither is safely possible, raise RuntimeError

Before finishing each test:
1. Re-read the user story line by line
2. Confirm every actionable line is represented in the test code
3. If any line is not yet covered by a POM call, add real Playwright for that line
4. Never leave a story line uncovered

The generated tests must be:
- POM-first
- Playwright-capable
- story-accurate
- executable
- complete

Now generate all three test functions only.


===========================================
🚫 SELECTOR OVERRIDE (MUST FOLLOW)
===========================================
Do NOT write any selector-based actions such as:
- page.click("css") / page.locator("css") / page.query_selector(...)
- Any placeholder like selector_for_* or 'Replace with actual selector'
If a required interaction cannot be expressed with the provided POM methods,
insert: raise RuntimeError("Missing POM method for <step>")
