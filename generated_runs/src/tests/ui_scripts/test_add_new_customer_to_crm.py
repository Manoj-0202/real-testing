# USER_STORY: Given I am on the CRM dashboard on https://bank-buddy-crm-react.lovable.app/ When I click the "Customers" button, And I click the "Add Customer" button, And I enter "John Doe" in the Full Name field, And I enter "john.doe@example.com" in the Email field, And I enter "1234567890" in the Phone Number field, And I select "Standard" for Account Type, And I enter "123 Main St, Anytown, USA" in the Address field, And I enter "Software Engineer" in the Occupation field, And I enter "75000" in the Annual Income field, And I enter "1000" in the Initial Deposit field, And I click the "Add Customer" button,

import pytest

from playwright.sync_api import sync_playwright, expect

import json

from pathlib import Path

from lib.smart_ai import patch_page_with_smartai

from pages.bank_addcustomer_page_methods import *

from pages.bank_customer_page_methods import *

from pages.bank_dashboard_page_methods import *

@pytest.mark.regression
def test_TS_001_TC_001_test_add_new_customer_to_crm_positive(page):
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


@pytest.mark.functional
def test_TS_001_TC_002_test_add_new_customer_to_crm_negative(page):
    page.goto("https://bank-buddy-crm-react.lovable.app/")
    click_customers(page)
    click_create_customer(page)
    enter_full_name(page, "!")  # Invalid: Empty name
    enter_email(page, "invalid-email")  # Invalid: Incorrect email format
    enter_phone_number(page, "123")  # Invalid: Too short phone number
    select_account_type(page, "Standard")
    enter_address(page, "123 Main St, Anytown, USA")
    enter_occupation(page, "Software Engineer")
    enter_annual_income(page, "75000")
    enter_initial_deposit(page, "1000")
    click_add_customer(page)
    # Assuming the form does not submit successfully due to validation errors


@pytest.mark.functional
def test_TS_001_TC_003_test_add_new_customer_to_crm_edge(page):
    page.goto("https://bank-buddy-crm-react.lovable.app/")
    click_customers(page)
    click_create_customer(page)
    enter_full_name(page, "John Doe")
    enter_email(page, "john.doe@example.com")
    enter_phone_number(page, "1234567890")
    select_account_type(page, "Standard")
    enter_address(page, "123 Main St, Anytown, USA")
    enter_occupation(page, "Software Engineer")
    enter_annual_income(page, "999999999")  # Edge: Large annual income
    enter_initial_deposit(page, "0")  # Edge: Minimum initial deposit
    click_add_customer(page)
