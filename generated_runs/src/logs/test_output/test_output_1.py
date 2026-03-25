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

def test_negative_feature(page):
    page.goto("https://bank-buddy-crm-react.lovable.app/")
    page.bank_customer.click_customers()
    page.bank_customer.click_create_customer()
    enter_full_name(page, "")  # Invalid: Empty name
    enter_email(page, "invalid-email")  # Invalid: Incorrect email format
    enter_phone_number(page, "123")  # Invalid: Too short phone number
    page.bank_addcustomer.select_account_type("Standard")
    page.bank_addcustomer.enter_address("123 Main St, Anytown, USA")
    page.bank_addcustomer.enter_occupation("Software Engineer")
    page.bank_addcustomer.enter_annual_income("75000")
    page.bank_addcustomer.enter_initial_deposit("1000")
    page.bank_addcustomer.click_add_customer()
    # Assuming the form does not submit successfully due to validation errors

def test_edge_feature(page):
    page.goto("https://bank-buddy-crm-react.lovable.app/")
    page.bank_customer.click_customers()
    page.bank_customer.click_create_customer()
    page.bank_addcustomer.enter_full_name("John Doe")
    page.bank_addcustomer.enter_email("john.doe@example.com")
    page.bank_addcustomer.enter_phone_number("1234567890")
    page.bank_addcustomer.select_account_type("Standard")
    page.bank_addcustomer.enter_address("123 Main St, Anytown, USA")
    page.bank_addcustomer.enter_occupation("Software Engineer")
    enter_annual_income(page, "999999999")  # Edge: Large annual income
    enter_initial_deposit(page, "0")  # Edge: Minimum initial deposit
    page.bank_addcustomer.click_add_customer()