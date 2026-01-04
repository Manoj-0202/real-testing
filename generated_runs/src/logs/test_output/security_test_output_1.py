def test_security_xss(page):
    page.goto("https://bank-buddy-crm-react.lovable.app/")
    page.on("dialog", lambda d: dialogs.append(d.message))
    dialogs = []

    # XSS payloads
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
        select_account_type(page, payload)

    click_add_customer(page)
    assert not dialogs


def test_security_sqli(page):
    page.goto("https://bank-buddy-crm-react.lovable.app/")

    # SQLi payloads
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
        select_account_type(page, payload)

    click_add_customer(page)
    assert "SQL" not in page.content()


def test_security_command_injection(page):
    page.goto("https://bank-buddy-crm-react.lovable.app/")

    # Command Injection payloads
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
        select_account_type(page, payload)

    click_add_customer(page)
    assert page.url != "" and page.title() != ""


def test_security_input_fuzzing(page):
    page.goto("https://bank-buddy-crm-react.lovable.app/")

    # Fuzzing payloads
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
        select_account_type(page, payload)

    click_add_customer(page)
    assert page.url != ""


def test_security_headers(page):
    response = page.goto("https://bank-buddy-crm-react.lovable.app/")
    headers = response.headers or {}

    assert "content-security-policy" in headers
    assert "x-frame-options" in headers
    assert "x-content-type-options" in headers
    if page.url.startswith("https"):
        assert "strict-transport-security" in headers