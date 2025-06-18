from lib.smart_ai import patch_page_with_smartai

# Assumes `page` has been patched already with patch_page_with_smartai(page, metadata)

def verify_your_cart(page):
    assert page.smartAI('saucedemo_cart_cart_header_your_cart').is_visible()

def verify_qty(page):
    assert page.smartAI('saucedemo_cart_quantity_header_qty').is_visible()

def verify_description(page):
    assert page.smartAI('saucedemo_cart_description_header_description').is_visible()

def enter_1(page, value):
    page.smartAI('saucedemo_cart_item_quantity_1').fill(value)

def verify_sauce_labs_backpack(page):
    assert page.smartAI('saucedemo_cart_item_name_sauce_labs_backpack').is_visible()

def verify_carry_allthethings_with_the_sleek_streamlined_sly_pack_that_melds_uncompromising_style_with_unequaled_laptop_and_tablet_protection(page):
    assert page.smartAI('saucedemo_cart_item_description_carry.allthethings()_with_the_sleek,_streamlined_sly_pack_that_melds_uncompromising_style_with_unequaled_laptop_and_tablet_protection.').is_visible()

def verify_29_99(page):
    assert page.smartAI('saucedemo_cart_price_label_$29.99').is_visible()

def click_remove(page):
    page.smartAI('saucedemo_cart_remove_item_remove').click()

def click_continue_shopping(page):
    page.smartAI('saucedemo_cart_continue_shopping_continue_shopping').click()

def click_checkout(page):
    page.smartAI('saucedemo_cart_checkout_checkout').click()

def verify_2025_sauce_labs_all_rights_reserved_terms_of_service_privacy_policy(page):
    assert page.smartAI('saucedemo_cart_footer_info_©_2025_sauce_labs._all_rights_reserved._terms_of_service_|_privacy_policy').is_visible()
