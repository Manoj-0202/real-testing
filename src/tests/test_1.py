from playwright.sync_api import sync_playwright

from pages.saucedemo_cart_page_methods import *

from pages.saucedemo_info_page_methods import *

from pages.saucedemo_login_page_methods import *

from pages.saucedemo_overview_page_methods import *

def test_positive_login_and_purchase_flow(page):
    enter_username(page, "standard_user")
    enter_password(page, "secret_sauce")
    click_login(page)
    verify_swag_labs(page)
    select_name_a_to_z(page)
    verify_sauce_labs_backpack(page)
    click_add_to_cart(page)
    verify_your_cart(page)
    click_checkout(page)
    verify_checkout_your_information(page)
    enter_first_name(page, "John")
    enter_last_name(page, "Doe")
    enter_zip_postal_code(page, "12345")
    click_continue(page)
    verify_products(page)
    click_finish(page)

def test_negative_invalid_login(page):
    enter_username(page, "invalid_user")
    enter_password(page, "wrong_password")
    click_login(page)
    verify_error_user(page)

def test_edge_case_long_username_and_fields(page):
    enter_username(page, "a" * 256)
    enter_password(page, "secret_sauce")
    click_login(page)
    verify_swag_labs(page)
    select_name_a_to_z(page)
    verify_sauce_labs_onesie(page)
    click_add_to_cart(page)
    click_checkout(page)
    verify_checkout_your_information(page)
    enter_first_name(page, "a" * 256)
    enter_last_name(page, "b" * 256)
    enter_zip_postal_code(page, "c" * 256)
    click_continue(page)
    verify_products(page)
    click_finish(page)