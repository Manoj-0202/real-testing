# USER_STORY: Given I am on the CRM dashboard on https://bank-buddy-crm-react.lovable.app/ When I click the "Customers" button, And I click the "Create Customer" button, And I enter "John Doe" in the Full Name field, And I enter "john.doe@example.com" in the Email field, And I enter "1234567890" in the Phone Number field, And I select "Standard" for Account Type, And I enter "123 Main St, Anytown, USA" in the Address field, And I enter "Software Engineer" in the Occupation field, And I enter "75000" in the Annual Income field, And I enter "1000" in the Initial Deposit field, And I click the "Add Customer" button,

import pytest

from playwright.sync_api import sync_playwright, expect

import json

from pathlib import Path

from lib.smart_ai import patch_page_with_smartai

from pages.bank_addcustomer_page_methods import *

from pages.bank_customer_page_methods import *

from pages.bank_dashboard_page_methods import *

@pytest.mark.regression
def test_TS_002_TC_001_test_add_new_customer_entry_positive(page):
    page.goto("https://bank-buddy-crm-react.lovable.app/")
    click_customers(page)
    click_create_customer(page)
    enter_full_name(page, "John Doe")
    enter_email(page, "john.doe@example.com")
    enter_phone_number(page, "1234567890")
    select_account_type(page, "Standard")
    enter_address(page, "123 Main St, Anytown, USA")
    enter_occupation(page, "Software Engineer")
    enter_annual_income(page, "75000")
    enter_initial_deposit(page, "1000")
    click_add_customer(page)
    # Assuming a success message or redirection is expected, but not specified in the story


@pytest.mark.functional
def test_TS_002_TC_002_test_add_new_customer_entry_negative(page):
    page.goto("https://bank-buddy-crm-react.lovable.app/")
    click_customers(page)
    click_create_customer(page)
    enter_full_name(page, "John Doe")
    enter_email(page, "invalid-email")  # Invalid email format
    enter_phone_number(page, "1234567890")
    select_account_type(page, "Standard")
    enter_address(page, "123 Main St, Anytown, USA")
    enter_occupation(page, "Software Engineer")
    enter_annual_income(page, "75000")
    enter_initial_deposit(page, "1000")
    click_add_customer(page)
    # Assuming an error message or validation failure is expected, but not specified in the story


@pytest.mark.functional
def test_TS_002_TC_003_test_add_new_customer_entry_edge(page):
    page.goto("https://bank-buddy-crm-react.lovable.app/")
    click_customers(page)
    click_create_customer(page)
    enter_full_name(page, "John Doe")
    enter_email(page, "john.doe@example.com")
    enter_phone_number(page, "123456789012345")  # Edge case: longer phone number
    select_account_type(page, "Standard")
    enter_address(page, "123 Main St, Anytown, USA")
    enter_occupation(page, "Software Engineer")
    enter_annual_income(page, "75000")
    enter_initial_deposit(page, "1000")
    click_add_customer(page)
    # Assuming stable behavior or specific handling for long phone numbers
