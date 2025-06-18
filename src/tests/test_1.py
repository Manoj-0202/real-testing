from playwright.sync_api import sync_playwright

from pages.saucedemo_cart_page_methods import *

from pages.saucedemo_info_page_methods import *

from pages.saucedemo_login_page_methods import *

from pages.saucedemo_overview_page_methods import *

def test_positive_order_product(page):
    page.goto("https://www.example.com")
    verify_swag_labs(page)
    enter_username(page, "standard_user")
    enter_password(page, "secret_sauce")
    click_login(page)
    verify_products(page)
    verify_sauce_labs_backpack(page)
    click_add_to_cart(page)
    verify_1_your_cart(page)
    click_10_checkout(page)
    verify_checkout_your_information(page)
    enter_first_name(page, "John")
    enter_last_name(page, "Doe")
    enter_zip_postal_code(page, "12345")
    click_continue(page)
    verify_sauce_labs_backpack(page)
    click_8_remove(page)

def test_negative_order_product_with_invalid_data(page):
    page.goto("https://www.example.com")
    verify_swag_labs(page)
    enter_username(page, "standard_user")
    enter_password(page, "wrong_password")
    click_login(page)
    verify_error_user(page)

def test_edge_order_product_with_special_characters(page):
    page.goto("https://www.example.com")
    verify_swag_labs(page)
    enter_username(page, "standard_user")
    enter_password(page, "secret_sauce")
    click_login(page)
    verify_products(page)
    verify_sauce_labs_backpack(page)
    click_add_to_cart(page)
    verify_1_your_cart(page)
    click_10_checkout(page)
    verify_checkout_your_information(page)
    enter_first_name(page, "!@#$%^")
    enter_last_name(page, "&*()")
    enter_zip_postal_code(page, "00000")
    click_continue(page)
    verify_3_description(page)