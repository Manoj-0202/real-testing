from playwright.sync_api import sync_playwright

from pages.saucedemo_info_page_methods import *

from pages.saucedemo_login_page_methods import *

from pages.saucedemo_overview_page_methods import *

def test_positive_login(page):
    page.goto("https://www.example.com")
    verify_swag_labs(page)
    enter_username(page, "standard_user")
    enter_password(page, "secret_sauce")
    click_login(page)
    verify_standard_user(page)

def test_negative_login(page):
    page.goto("https://www.example.com")
    verify_swag_labs(page)
    enter_username(page, "invalid_user")
    enter_password(page, "invalid_password")
    click_login(page)
    verify_error_user(page)

def test_edge_login(page):
    page.goto("https://www.example.com")
    verify_swag_labs(page)
    enter_username(page, "")
    enter_password(page, "")
    click_login(page)
    verify_error_user(page)

def test_positive_add_to_cart(page):
    page.goto("https://www.example.com")
    verify_swag_labs(page)
    enter_username(page, "standard_user")
    enter_password(page, "secret_sauce")
    click_login(page)
    click_5_add_to_cart(page)
    verify_3_sauce_labs_backpack(page)

def test_negative_add_to_cart(page):
    page.goto("https://www.example.com")
    verify_swag_labs(page)
    enter_username(page, "standard_user")
    enter_password(page, "secret_sauce")
    click_login(page)
    # no product selected
    click_continue(page)  # Assuming this is supposed to move to cart page or next step

def test_edge_add_to_cart(page):
    page.goto("https://www.example.com")
    verify_swag_labs(page)
    enter_username(page, "standard_user")
    enter_password(page, "secret_sauce")
    click_login(page)
    click_5_add_to_cart(page)
    click_8_add_to_cart(page)
    click_11_add_to_cart(page)
    click_14_add_to_cart(page)
    verify_1_products(page)

def test_positive_checkout(page):
    page.goto("https://www.example.com")
    verify_swag_labs(page)
    enter_username(page, "standard_user")
    enter_password(page, "secret_sauce")
    click_login(page)
    click_5_add_to_cart(page)
    click_continue(page)
    verify_checkout_your_information(page)
    enter_first_name(page, "John")
    enter_last_name(page, "Doe")
    enter_zip_postal_code(page, "12345")
    click_continue(page)

def test_negative_checkout(page):
    page.goto("https://www.example.com")
    verify_swag_labs(page)
    enter_username(page, "standard_user")
    enter_password(page, "secret_sauce")
    click_login(page)
    click_5_add_to_cart(page)
    click_continue(page)
    verify_checkout_your_information(page)
    enter_first_name(page, "")
    enter_last_name(page, "")
    enter_zip_postal_code(page, "")
    click_continue(page)
    verify_error_user(page)

def test_edge_checkout(page):
    page.goto("https://www.example.com")
    verify_swag_labs(page)
    enter_username(page, "standard_user")
    enter_password(page, "secret_sauce")
    click_login(page)
    click_5_add_to_cart(page)
    click_continue(page)
    verify_checkout_your_information(page)
    enter_first_name(page, "A" * 256)
    enter_last_name(page, "B" * 256)
    enter_zip_postal_code(page, "C" * 20)
    click_continue(page)
    verify_error_user(page)