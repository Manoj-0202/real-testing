from lib.smart_ai import patch_page_with_smartai

# Assumes `page` has been patched already with patch_page_with_smartai(page, metadata)

def verify_checkout_your_information(page):
    assert page.smartAI('saucedemo_info_instruction_checkout:_your_information').is_visible()

def enter_first_name(page, value):
    page.smartAI('saucedemo_info_first_name_first_name').fill(value)

def enter_last_name(page, value):
    page.smartAI('saucedemo_info_last_name_last_name').fill(value)

def enter_zip_postal_code(page, value):
    page.smartAI('saucedemo_info_postal_code_zip/postal_code').fill(value)

def click_cancel(page):
    page.smartAI('saucedemo_info_cancel_cancel').click()

def click_continue(page):
    page.smartAI('saucedemo_info_continue_continue').click()
