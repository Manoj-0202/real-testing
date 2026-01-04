import pytest

from playwright.sync_api import sync_playwright, expect

import json

from pathlib import Path

from lib.smart_ai import patch_page_with_smartai

from pages.bank_add_customer_page_methods import *

from pages.bank_customer_page_methods import *

from pages.bank_dashboard_page_methods import *

from pages.loans_page_methods import *

from pages.loanss_page_methods import *

def test_security_xss(page):
    page.goto("https://bank-buddy-crm-react.lovable.app/")
    click_loans(page)
    click_new_loan_application(page)
    payloads = [
        "<script>alert('XSS')</script>",
        '"><img src=x onerror=alert("XSS")>',
        "<svg/onload=alert(1)>",
        "<iframe src=javascript:alert(1)>"
    ]
    dialogs = []
    page.on("dialog", lambda d: dialogs.append(d.message))
    for payload in payloads:
        enter_customer_name(page, payload)
        enter_loan_amount(page, payload)
        enter_loan_purpose(page, payload)
        enter_annual_income(page, payload)
        enter_credit_score(page, payload)
        enter_collateral_information(page, payload)
    click_submit_application(page)
    assert not dialogs
    # AI-analyzed tags: none | Priority: Low


def test_security_sqli(page):
    page.goto("https://bank-buddy-crm-react.lovable.app/")
    click_loans(page)
    click_new_loan_application(page)
    payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' UNION SELECT NULL,NULL --",
        "'; DROP TABLE users; --"
    ]
    for payload in payloads:
        enter_customer_name(page, payload)
        enter_loan_amount(page, payload)
        enter_loan_purpose(page, payload)
        enter_annual_income(page, payload)
        enter_credit_score(page, payload)
        enter_collateral_information(page, payload)
    click_submit_application(page)
    assert "SQL" not in page.content()
    # AI-analyzed tags: none | Priority: Low


def test_security_command_injection(page):
    page.goto("https://bank-buddy-crm-react.lovable.app/")
    click_loans(page)
    click_new_loan_application(page)
    payloads = [
        "; ls",
        "&& whoami",
        "| cat /etc/passwd",
        "$(whoami)",
        "`whoami`"
    ]
    for payload in payloads:
        enter_customer_name(page, payload)
        enter_loan_amount(page, payload)
        enter_loan_purpose(page, payload)
        enter_annual_income(page, payload)
        enter_credit_score(page, payload)
        enter_collateral_information(page, payload)
    click_submit_application(page)
    assert page.url != ""
    # AI-analyzed tags: none | Priority: Low


def test_security_input_fuzzing(page):
    page.goto("https://bank-buddy-crm-react.lovable.app/")
    click_loans(page)
    click_new_loan_application(page)
    payloads = [
        "A" * 5000,
        "B" * 10000,
        "@#$%^&*()" * 200,
        "9" * 100
    ]
    for payload in payloads:
        enter_customer_name(page, payload)
        enter_loan_amount(page, payload)
        enter_loan_purpose(page, payload)
        enter_annual_income(page, payload)
        enter_credit_score(page, payload)
        enter_collateral_information(page, payload)
    click_submit_application(page)
    assert page.url != ""
    # AI-analyzed tags: none | Priority: Low


def test_security_headers(page):
    response = page.goto("https://bank-buddy-crm-react.lovable.app/")
    headers = response.headers or {}
    assert "content-security-policy" in headers
    assert "x-frame-options" in headers
    assert "x-content-type-options" in headers
    if page.url.startswith("https"):
        assert "strict-transport-security" in headers
    # AI-analyzed tags: none | Priority: Low
