from lib.smart_ai import patch_page_with_smartai

# Assumes `page` has been patched already with patch_page_with_smartai(page, metadata)

def verify_1_your_cart(page):
    assert page.smartAI('saucedemo_cart_cart_title_1._your_cart').is_visible()

def verify_2_qty(page):
    assert page.smartAI('saucedemo_cart_quantity_label_2._qty').is_visible()

def verify_3_description(page):
    assert page.smartAI('saucedemo_cart_description_label_3._description').is_visible()

def enter_4_1(page, value):
    page.smartAI('saucedemo_cart_item_quantity_4._1').fill(value)

def verify_5_sauce_labs_backpack(page):
    assert page.smartAI('saucedemo_cart_item_name_5._sauce_labs_backpack').is_visible()

def verify_6_carry_allthethings_with_the_sleek_streamlined_sly_pack_that_melds_uncompromising_style_with_unequaled_laptop_and_tablet_protection(page):
    assert page.smartAI('saucedemo_cart_item_description_6._carry.allthethings()_with_the_sleek,_streamlined_sly_pack_that_melds_uncompromising_style_with_unequaled_laptop_and_tablet_protection.').is_visible()

def verify_7_29_99(page):
    assert page.smartAI('saucedemo_cart_item_price_7._$29.99').is_visible()

def click_8_remove(page):
    page.smartAI('saucedemo_cart_remove_item_8._remove').click()

def click_9_continue_shopping(page):
    page.smartAI('saucedemo_cart_continue_shopping_9._continue_shopping').click()

def click_10_checkout(page):
    page.smartAI('saucedemo_cart_proceed_to_checkout_10._checkout').click()
