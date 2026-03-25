# USER_STORY: Given I am on the https://asi.paygov.org.in/ And I verify "ARCHAEOLOGICAL SURVEY OF INDIA" is visible , And I check "Delhi" checkbox, And I check "Jantar Mantar" checkbox, And I select "Afternoon" in "Visit time" field, And I click on "Proceed" button, And I verify "Note: Adult age above 15 yrs & child age below 15 yrs And I enter "abcd" in "Name" field, And I enter "33" in "Age" field, And I enter "asfb@gmail.com" in "Email" field, And I enter "7897852147" in "Mobile No" field, And I click on "Proceed to pay" button And I enter "473424243342" in "Card Number" field, And I select "12" for "Expiry Month", And I select "2033" for "Expiry Year" And I enter "Abcd" in "Name on Card" field, And I enter "123" in "CVV" field, And I click "Pay Now" button

import pytest

from playwright.sync_api import sync_playwright, expect

import json

from pathlib import Path

from lib.smart_ai import patch_page_with_smartai

from pages.first_page_methods import *

from pages.secnd_page_methods import *

from pages.third_page_methods import *

@pytest.mark.regression
def test_TS_001_TC_001_test_book_jantar_mantar_afternoon_visit_positive(page):
    page.goto("https://asi.paygov.org.in/")
    expect(page.get_by_text("ARCHAEOLOGICAL SURVEY OF INDIA", exact=True).first).to_be_visible()
    check_delhi(page)
    check_checkbox(page, "Jantar Mantar")
    select_dropdown(page, "Visit time", "Afternoon")
    click_proceed_to_pay(page)
    expect(page.get_by_text("Note: Adult age above 15 yrs & child age below 15 yrs", exact=True).first).to_be_visible()
    enter_name(page, "abcd")
    enter_age(page, "33")
    enter_email(page, "asfb@gmail.com")
    enter_mobile_no(page, "7897852147")
    click_proceed_to_pay(page)
    enter_card_number(page, "473424243342")
    select_expiry_month_mm(page, "12")
    select_expiry_year_yyyy(page, "2033")
    enter_name_on_card(page, "Abcd")
    enter_cvv(page, "123")
    click_pay_now(page)


@pytest.mark.functional
def test_TS_001_TC_002_test_book_jantar_mantar_afternoon_visit_negative(page):
    page.goto("https://asi.paygov.org.in/")
    expect(page.get_by_text("ARCHAEOLOGICAL SURVEY OF INDIA", exact=True).first).to_be_visible()
    check_delhi(page)
    check_checkbox(page, "Jantar Mantar")
    select_dropdown(page, "Visit time", "Afternoon")
    click_proceed_to_pay(page)
    expect(page.get_by_text("Note: Adult age above 15 yrs & child age below 15 yrs", exact=True).first).to_be_visible()
    enter_name(page, "!")  # Invalid name
    enter_age(page, "33")
    enter_email(page, "asfb@gmail.com")
    enter_mobile_no(page, "7897852147")
    click_proceed_to_pay(page)
    expect(page.get_by_text("Please enter a valid name", exact=True).first).to_be_visible()


@pytest.mark.functional
def test_TS_001_TC_003_test_book_jantar_mantar_afternoon_visit_edge(page):
    page.goto("https://asi.paygov.org.in/")
    expect(page.get_by_text("ARCHAEOLOGICAL SURVEY OF INDIA", exact=True).first).to_be_visible()
    check_delhi(page)
    check_checkbox(page, "Jantar Mantar")
    select_dropdown(page, "Visit time", "Afternoon")
    click_proceed_to_pay(page)
    expect(page.get_by_text("Note: Adult age above 15 yrs & child age below 15 yrs", exact=True).first).to_be_visible()
    enter_name(page, "a" * 255)  # Edge case: long name
    enter_age(page, "15")  # Edge case: boundary age
    enter_email(page, "asfb@gmail.com")
    enter_mobile_no(page, "7897852147")
    click_proceed_to_pay(page)
    enter_card_number(page, "473424243342")
    select_expiry_month_mm(page, "12")
    select_expiry_year_yyyy(page, "2033")
    enter_name_on_card(page, "Abcd")
    enter_cvv(page, "123")
    click_pay_now(page)
