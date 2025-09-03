from services.page_enricher import enrich_page

class BasePage:
    enriched_pages = set()

    def __init__(self, page, page_name, url=None):
        self.page = page
        self.page_name = page_name
        self.url = url

    async def goto(self, url=None):
        if url:
            await self.page.goto(url)
        elif self.url:
            await self.page.goto(self.url)
        else:
            raise ValueError(f"URL not set for {self.page_name}")

    async def enrich_once(self, force=False):
        if force or self.page_name not in BasePage.enriched_pages:
            await enrich_page(self.page, self.page_name)  # DOM enrichment clearly triggered
            BasePage.enriched_pages.add(self.page_name)
            print(f"🌟 Enriched page: {self.page_name}")
        else:
            print(f"✅ Already enriched: {self.page_name}")