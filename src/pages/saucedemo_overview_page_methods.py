from lib.smart_ai import patch_page_with_smartai

# Assumes `page` has been patched already with patch_page_with_smartai(page, metadata)

def verify_products(page):
    assert page.smartAI('saucedemo_overview_title_products').is_visible()

def verify_sauce_labs_backpack(page):
    assert page.smartAI('saucedemo_overview_product_name_sauce_labs_backpack').is_visible()

def verify_29_99(page):
    assert page.smartAI('saucedemo_overview_price_label_$29.99').is_visible()

def click_add_to_cart(page):
    page.smartAI('saucedemo_overview_add_to_cart_add_to_cart').click()

def verify_sauce_labs_bike_light(page):
    assert page.smartAI('saucedemo_overview_product_name_sauce_labs_bike_light').is_visible()

def verify_9_99(page):
    assert page.smartAI('saucedemo_overview_price_label_$9.99').is_visible()

def click_add_to_cart(page):
    page.smartAI('saucedemo_overview_add_to_cart_add_to_cart').click()

def verify_sauce_labs_bolt_t_shirt(page):
    assert page.smartAI('saucedemo_overview_product_name_sauce_labs_bolt_t-shirt').is_visible()

def verify_15_99(page):
    assert page.smartAI('saucedemo_overview_price_label_$15.99').is_visible()

def click_add_to_cart(page):
    page.smartAI('saucedemo_overview_add_to_cart_add_to_cart').click()

def verify_sauce_labs_fleece_jacket(page):
    assert page.smartAI('saucedemo_overview_product_name_sauce_labs_fleece_jacket').is_visible()

def verify_49_99(page):
    assert page.smartAI('saucedemo_overview_price_label_$49.99').is_visible()

def click_add_to_cart(page):
    page.smartAI('saucedemo_overview_add_to_cart_add_to_cart').click()

def verify_sauce_labs_onesie(page):
    assert page.smartAI('saucedemo_overview_product_name_sauce_labs_onesie').is_visible()

def verify_test_allthethings_t_shirt_red(page):
    assert page.smartAI('saucedemo_overview_product_name_test.allthethings()_t-shirt_(red)').is_visible()

def select_name_a_to_z(page, value):
    page.smartAI('saucedemo_overview_sort_options_name_(a_to_z)').select_option(value)
