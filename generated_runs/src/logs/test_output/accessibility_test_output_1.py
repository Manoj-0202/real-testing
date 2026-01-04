def test_a11y_non_text_content(page):
    page.goto("https://bank-buddy-crm-react.lovable.app/")
    bank_dashboard.verify_bank_crm_visible(page)
    bank_dashboard.click_customers(page)
    bank_customer.click_add_new_customer(page)
    expect(page.locator("img:not([alt])")._locator).to_have_count(0)

def test_a11y_info_and_relationships(page):
    page.goto("https://bank-buddy-crm-react.lovable.app/")
    bank_dashboard.verify_bank_crm_visible(page)
    bank_dashboard.click_customers(page)
    bank_customer.click_add_new_customer(page)
    inputs = page.locator("input")
    unlabeled_count = inputs.evaluate_all(
        "els => els.filter(e => !e.labels || e.labels.length === 0).length"
    )
    assert unlabeled_count == 0

def test_a11y_identify_input_purpose(page):
    page.goto("https://bank-buddy-crm-react.lovable.app/")
    bank_dashboard.verify_bank_crm_visible(page)
    bank_dashboard.click_customers(page)
    bank_customer.click_add_new_customer(page)
    email_input = page.locator("input[type='email']")
    expect(email_input._locator).to_have_attribute("autocomplete", re.compile(r".*"))
    password_input = page.locator("input[type='password']")
    expect(password_input._locator).to_have_attribute("autocomplete", re.compile(r".*"))
    username_input = page.locator("input[name='username']")
    if username_input.count() > 0:
        expect(username_input._locator).to_have_attribute("autocomplete", re.compile(r".*"))

def test_a11y_keyboard_access(page):
    page.goto("https://bank-buddy-crm-react.lovable.app/")
    bank_dashboard.verify_bank_crm_visible(page)
    bank_dashboard.click_customers(page)
    bank_customer.click_add_new_customer(page)
    before = page.evaluate("document.activeElement && document.activeElement.tagName")
    page.keyboard.press("Tab")
    after = page.evaluate("document.activeElement && document.activeElement.tagName")
    assert before != after

def test_a11y_no_keyboard_trap(page):
    page.goto("https://bank-buddy-crm-react.lovable.app/")
    bank_dashboard.verify_bank_crm_visible(page)
    bank_dashboard.click_customers(page)
    bank_customer.click_add_new_customer(page)
    start = page.evaluate("document.activeElement && document.activeElement.tagName")
    page.keyboard.press("Tab")
    forward = page.evaluate("document.activeElement && document.activeElement.tagName")
    page.keyboard.press("Shift+Tab")
    backward = page.evaluate("document.activeElement && document.activeElement.tagName")
    assert start != forward
    assert start == backward

def test_a11y_page_title(page):
    page.goto("https://bank-buddy-crm-react.lovable.app/")
    bank_dashboard.verify_bank_crm_visible(page)
    bank_dashboard.click_customers(page)
    bank_customer.click_add_new_customer(page)
    title = page.evaluate("document.title")
    assert title
    assert len(title) > 3

def test_a11y_language_of_page(page):
    page.goto("https://bank-buddy-crm-react.lovable.app/")
    bank_dashboard.verify_bank_crm_visible(page)
    bank_dashboard.click_customers(page)
    bank_customer.click_add_new_customer(page)
    expect(page.locator("html")._locator).to_have_attribute("lang", re.compile(r".*"))