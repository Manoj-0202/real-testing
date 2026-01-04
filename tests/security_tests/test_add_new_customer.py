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


def test_security_sqli(page):
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


def test_security_command_injection(page):
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


def test_security_input_fuzzing(page):
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


def test_security_headers(page):
    response = page.goto("https://bank-buddy-crm-react.lovable.app/")
    headers = response.headers or {}
    
    assert "content-security-policy" in headers
    assert "x-frame-options" in headers
    assert "x-content-type-options" in headers
    if page.url().startswith("https"):
        assert "strict-transport-security" in headers
    # AI-analyzed tags: none | Priority: Low
