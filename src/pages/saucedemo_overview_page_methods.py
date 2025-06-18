from lib.smart_ai import patch_page_with_smartai

# Assumes `page` has been patched already with patch_page_with_smartai(page, metadata)

def verify_1_products(page):
    assert page.smartAI('saucedemo_overview_heading_1._products').is_visible()

def select_2_name_a_to_z(page, value):
    page.smartAI('saucedemo_overview_sort_options_2._name_(a_to_z)').select_option(value)

def verify_3_sauce_labs_backpack(page):
    assert page.smartAI('saucedemo_overview_product_name_3._sauce_labs_backpack').is_visible()

def verify_4_29_99(page):
    assert page.smartAI('saucedemo_overview_price_label_4._$29.99').is_visible()

def click_5_add_to_cart(page):
    page.smartAI('saucedemo_overview_add_to_cart_5._add_to_cart').click()

def verify_6_sauce_labs_bike_light(page):
    assert page.smartAI('saucedemo_overview_product_name_6._sauce_labs_bike_light').is_visible()

def verify_7_9_99(page):
    assert page.smartAI('saucedemo_overview_price_label_7._$9.99').is_visible()

def click_8_add_to_cart(page):
    page.smartAI('saucedemo_overview_add_to_cart_8._add_to_cart').click()

def verify_9_sauce_labs_bolt_t_shirt(page):
    assert page.smartAI('saucedemo_overview_product_name_9._sauce_labs_bolt_t-shirt').is_visible()

def verify_10_15_99(page):
    assert page.smartAI('saucedemo_overview_price_label_10._$15.99').is_visible()

def click_11_add_to_cart(page):
    page.smartAI('saucedemo_overview_add_to_cart_11._add_to_cart').click()

def verify_12_sauce_labs_fleece_jacket(page):
    assert page.smartAI('saucedemo_overview_product_name_12._sauce_labs_fleece_jacket').is_visible()

def verify_13_49_99(page):
    assert page.smartAI('saucedemo_overview_price_label_13._$49.99').is_visible()

def click_14_add_to_cart(page):
    page.smartAI('saucedemo_overview_add_to_cart_14._add_to_cart').click()

def verify_15_sauce_labs_onesie(page):
    assert page.smartAI('saucedemo_overview_product_name_15._sauce_labs_onesie').is_visible()

def verify_16_test_allthethings_t_shirt_red(page):
    assert page.smartAI('saucedemo_overview_product_name_16._test.allthethings()_t-shirt_(red)').is_visible()
