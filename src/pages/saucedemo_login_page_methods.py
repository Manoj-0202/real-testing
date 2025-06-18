from lib.smart_ai import patch_page_with_smartai

# Assumes `page` has been patched already with patch_page_with_smartai(page, metadata)

def verify_swag_labs(page):
    assert page.smartAI('saucedemo_login_heading_swag_labs').is_visible()

def enter_username(page, value):
    page.smartAI('saucedemo_login_username_username').fill(value)

def enter_password(page, value):
    page.smartAI('saucedemo_login_password_password').fill(value)

def click_login(page):
    page.smartAI('saucedemo_login_login_login').click()

def verify_accepted_usernames_are(page):
    assert page.smartAI('saucedemo_login_username_info_accepted_usernames_are:').is_visible()

def verify_standard_user(page):
    assert page.smartAI('saucedemo_login_username_info_standard_user').is_visible()

def verify_locked_out_user(page):
    assert page.smartAI('saucedemo_login_username_info_locked_out_user').is_visible()

def verify_problem_user(page):
    assert page.smartAI('saucedemo_login_username_info_problem_user').is_visible()

def verify_performance_glitch_user(page):
    assert page.smartAI('saucedemo_login_username_info_performance_glitch_user').is_visible()

def verify_error_user(page):
    assert page.smartAI('saucedemo_login_username_info_error_user').is_visible()

def verify_visual_user(page):
    assert page.smartAI('saucedemo_login_username_info_visual_user').is_visible()

def verify_password_for_all_users(page):
    assert page.smartAI('saucedemo_login_password_info_password_for_all_users:').is_visible()

def verify_secret_sauce(page):
    assert page.smartAI('saucedemo_login_password_info_secret_sauce').is_visible()
