def test_positive_feature(page):
    page.goto("https://bank-buddy-crm-react.lovable.app/")
    page.bank_customer.click_customers()
    page.bank_customer.click_create_customer()
    page.bank_addcustomer.enter_full_name("John Doe")
    page.bank_addcustomer.enter_email("john.doe@example.com")
    page.bank_addcustomer.enter_phone_number("1234567890")
    page.bank_addcustomer.select_account_type("Standard")
    page.bank_addcustomer.enter_address("123 Main St, Anytown, USA")
    page.bank_addcustomer.enter_occupation("Software Engineer")
    page.bank_addcustomer.enter_annual_income("75000")
    page.bank_addcustomer.enter_initial_deposit("1000")
    page.bank_addcustomer.click_add_customer()
    # Assuming a success message or redirection is expected, but not specified in the story

def test_negative_feature(page):
    page.goto("https://bank-buddy-crm-react.lovable.app/")
    page.bank_customer.click_customers()
    page.bank_customer.click_create_customer()
    page.bank_addcustomer.enter_full_name("John Doe")
    enter_email(page, "invalid-email")  # Invalid email format
    page.bank_addcustomer.enter_phone_number("1234567890")
    page.bank_addcustomer.select_account_type("Standard")
    page.bank_addcustomer.enter_address("123 Main St, Anytown, USA")
    page.bank_addcustomer.enter_occupation("Software Engineer")
    page.bank_addcustomer.enter_annual_income("75000")
    page.bank_addcustomer.enter_initial_deposit("1000")
    page.bank_addcustomer.click_add_customer()
    # Assuming an error message or validation failure is expected, but not specified in the story

def test_edge_feature(page):
    page.goto("https://bank-buddy-crm-react.lovable.app/")
    page.bank_customer.click_customers()
    page.bank_customer.click_create_customer()
    page.bank_addcustomer.enter_full_name("John Doe")
    page.bank_addcustomer.enter_email("john.doe@example.com")
    enter_phone_number(page, "123456789012345")  # Edge case: longer phone number
    page.bank_addcustomer.select_account_type("Standard")
    page.bank_addcustomer.enter_address("123 Main St, Anytown, USA")
    page.bank_addcustomer.enter_occupation("Software Engineer")
    page.bank_addcustomer.enter_annual_income("75000")
    page.bank_addcustomer.enter_initial_deposit("1000")
    page.bank_addcustomer.click_add_customer()
    # Assuming stable behavior or specific handling for long phone numbers