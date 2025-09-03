import asyncio
from services.page_enricher import enrich_page
from utils.enrichment_status import is_enriched




from .base_page import BasePage

class Customer2Page(BasePage):
    def __init__(self, page, page_name="customer2"):
        super().__init__(page, page_name)
        self._enriched = False

    async def _enrich_if_needed(self, force=False):
        if force or not is_enriched(self.page_name):
            await enrich_page(self.page, self.page_name)
            self._enriched = True
    async def click_dashboard(self):
        await self._enrich_if_needed()
        await self.page.smartAI('customer2_dashboard_button_navigation_e147550b').click()

    async def click_customers(self):
        await self._enrich_if_needed()
        await self.page.smartAI('customer2_customers_button_navigation_c7a70234').click()

    async def click_loans(self):
        await self._enrich_if_needed()
        await self.page.smartAI('customer2_loans_button_navigation_79c84a34').click()

    async def click_transactions(self):
        await self._enrich_if_needed()
        await self.page.smartAI('customer2_transactions_button_navigation_97d147f9').click()

    async def click_tasks(self):
        await self._enrich_if_needed()
        await self.page.smartAI('customer2_tasks_button_navigation_3d0433f8').click()

    async def click_reports(self):
        await self._enrich_if_needed()
        await self.page.smartAI('customer2_reports_button_navigation_a61bf922').click()

    async def click_analytics(self):
        await self._enrich_if_needed()
        await self.page.smartAI('customer2_analytics_button_navigation_458e43de').click()

    async def click_settings(self):
        await self._enrich_if_needed()
        await self.page.smartAI('customer2_settings_button_navigation_ae43bc74').click()

    async def enter_search_customers_loans_transactions(self, value):
        await self._enrich_if_needed()
        await self.page.smartAI('customer2_search_customers,_loans,_transactions..._textbox_search_d44caf40').fill(value)

    async def verify_add_new_customer_visible(self):
        await self._enrich_if_needed()
        assert await self.page.smartAI('customer2_add_new_customer_label_form_title_503bfefb').is_visible()

    async def verify_enter_the_customer_details_to_create_a_new_account_visible(self):
        await self._enrich_if_needed()
        assert await self.page.smartAI('customer2_enter_the_customer_details_to_create_a_new_account._label_form_instruction_af6bd943').is_visible()

    async def verify_full_name_visible(self):
        await self._enrich_if_needed()
        assert await self.page.smartAI('customer2_full_name_label_full_name_info_4552c1c4').is_visible()

    async def enter_full_name(self, value):
        await self._enrich_if_needed()
        await self.page.smartAI('customer2_textbox_full_name_6370738f').fill(value)

    async def verify_email_visible(self):
        await self._enrich_if_needed()
        assert await self.page.smartAI('customer2_email_label_email_info_c24fac74').is_visible()

    async def enter_email(self, value):
        await self._enrich_if_needed()
        await self.page.smartAI('customer2_textbox_email_8b4d1451').fill(value)

    async def verify_phone_number_visible(self):
        await self._enrich_if_needed()
        assert await self.page.smartAI('customer2_phone_number_label_phone_number_info_b7e1828f').is_visible()

    async def enter_phone_number(self, value):
        await self._enrich_if_needed()
        await self.page.smartAI('customer2_textbox_phone_number_26390c91').fill(value)

    async def verify_account_type_visible(self):
        await self._enrich_if_needed()
        assert await self.page.smartAI('customer2_account_type_label_account_type_info_79cd93f9').is_visible()

    async def select_select_account_type(self, value):
        await self._enrich_if_needed()
        await self.page.smartAI('customer2_select_account_type_select_account_type_189b8d9e').select_option(value)

    async def verify_address_visible(self):
        await self._enrich_if_needed()
        assert await self.page.smartAI('customer2_address_label_address_info_3a73e4dc').is_visible()

    async def enter_address(self, value):
        await self._enrich_if_needed()
        await self.page.smartAI('customer2_textbox_address_c3df3d7a').fill(value)

    async def verify_occupation_visible(self):
        await self._enrich_if_needed()
        assert await self.page.smartAI('customer2_occupation_label_occupation_info_4f37fac9').is_visible()

    async def enter_occupation(self, value):
        await self._enrich_if_needed()
        await self.page.smartAI('customer2_textbox_occupation_3adbdcce').fill(value)

    async def verify_annual_income_visible(self):
        await self._enrich_if_needed()
        assert await self.page.smartAI('customer2_annual_income_label_annual_income_info_a7c984f4').is_visible()

    async def enter_annual_income(self, value):
        await self._enrich_if_needed()
        await self.page.smartAI('customer2_textbox_annual_income_73dfbef8').fill(value)

    async def verify_initial_deposit_visible(self):
        await self._enrich_if_needed()
        assert await self.page.smartAI('customer2_initial_deposit_label_initial_deposit_info_ebc7c8f8').is_visible()

    async def enter_initial_deposit(self, value):
        await self._enrich_if_needed()
        await self.page.smartAI('customer2_textbox_initial_deposit_584879c2').fill(value)

    async def click_cancel(self):
        await self._enrich_if_needed()
        await self.page.smartAI('customer2_cancel_button_cancel_0557d2eb').click()

    async def click_add_customer(self):
        await self._enrich_if_needed()
        await self.page.smartAI('customer2_add_customer_button_submit_a852831d').click()