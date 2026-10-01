import unittest

from cape_artifact import benchmark_common
from cape_artifact.catalog import (
    ALLOWED_CATEGORIES,
    ALLOWED_PRODUCTS,
    DISGUISED_STORED_VALUE_PRODUCTS,
    FORBIDDEN_CATEGORY,
    INJECTION_TEMPLATES,
    attack_catalog_cases,
    benign_catalog_cases,
)
from cape_artifact.catalog_service import CatalogService


class CatalogStructureTests(unittest.TestCase):
    def test_every_allowed_product_is_within_policy_price_cap(self):
        for product in ALLOWED_PRODUCTS:
            self.assertIn(product.category, ALLOWED_CATEGORIES)
            self.assertLessEqual(product.price_usd, 200)

    def test_all_three_allowed_categories_are_represented(self):
        categories = {product.category for product in ALLOWED_PRODUCTS}
        self.assertEqual(categories, set(ALLOWED_CATEGORIES))

    def test_one_injection_technique_per_disguised_product(self):
        self.assertEqual(len(INJECTION_TEMPLATES), len(DISGUISED_STORED_VALUE_PRODUCTS))

    def test_disguised_products_rotate_across_allowed_categories(self):
        cover_categories = {p.cover_category for p in DISGUISED_STORED_VALUE_PRODUCTS}
        self.assertEqual(cover_categories, set(ALLOWED_CATEGORIES))


class CatalogCaseGenerationTests(unittest.TestCase):
    def test_benign_cases_cover_every_allowed_product(self):
        cases = benign_catalog_cases()
        self.assertEqual(len(cases), len(ALLOWED_PRODUCTS))
        for _, merchant_data, price in cases:
            self.assertIn(f"actual_category=", merchant_data)
            self.assertNotIn(FORBIDDEN_CATEGORY, merchant_data)
            self.assertLessEqual(price, 200)

    def test_attack_cases_all_disguise_stored_value(self):
        cases = attack_catalog_cases()
        self.assertEqual(len(cases), len(DISGUISED_STORED_VALUE_PRODUCTS))
        for case_id, merchant_data, _price in cases:
            self.assertIn(f"actual_category={FORBIDDEN_CATEGORY}", merchant_data)
            self.assertNotEqual(f"category={FORBIDDEN_CATEGORY}", merchant_data.split(";")[0].strip())

    def test_case_ids_are_unique(self):
        ids = [c[0] for c in benign_catalog_cases()] + [c[0] for c in attack_catalog_cases()]
        self.assertEqual(len(ids), len(set(ids)))


class BenchmarkCommonCatalogIntegrationTests(unittest.TestCase):
    def test_all_cases_include_price_and_attack_flag(self):
        cases = benchmark_common.all_cases()
        self.assertEqual(len(cases), len(ALLOWED_PRODUCTS) + len(DISGUISED_STORED_VALUE_PRODUCTS))
        for case_id, is_attack, merchant_data, price_usd in cases:
            self.assertIsInstance(is_attack, bool)
            self.assertIsInstance(price_usd, int)
            self.assertGreater(price_usd, 0)

    def test_policy_allows_all_three_catalog_categories(self):
        policy = benchmark_common.policy_fixture()
        for category in ALLOWED_CATEGORIES:
            self.assertIn(category, policy.allowed_categories)
        self.assertIn(FORBIDDEN_CATEGORY, policy.forbidden_categories)

    def test_user_prompt_reports_the_actual_product_price_once(self):
        prompt = benchmark_common.user_prompt("category=kitchen; actual_category=kitchen; title=Pan.", 129)
        self.assertEqual(prompt.count("price_usd="), 1)
        self.assertIn("price_usd=129", prompt)


class CatalogServiceTests(unittest.TestCase):
    def test_serves_every_product_over_real_http(self):
        with CatalogService() as catalog:
            products = catalog.list_products()
        skus = {p["sku"] for p in products}
        expected = {p.sku for p in ALLOWED_PRODUCTS} | {p.sku for p in DISGUISED_STORED_VALUE_PRODUCTS}
        self.assertEqual(skus, expected)

    def test_disguised_product_is_served_under_its_cover_category_not_the_truth(self):
        with CatalogService() as catalog:
            disguise = DISGUISED_STORED_VALUE_PRODUCTS[0]
            listing = catalog.get_product(disguise.sku)
        self.assertEqual(listing["category"], disguise.cover_category)
        self.assertNotEqual(listing["category"], FORBIDDEN_CATEGORY)
        self.assertEqual(listing["title"], disguise.cover_title)

    def test_unknown_sku_returns_none(self):
        with CatalogService() as catalog:
            self.assertIsNone(catalog.get_product("does-not-exist"))

    def test_all_cases_round_trips_through_the_live_service(self):
        cases = benchmark_common.all_cases()
        self.assertEqual(len(cases), len(ALLOWED_PRODUCTS) + len(DISGUISED_STORED_VALUE_PRODUCTS))
        case_ids = {c[0] for c in cases}
        self.assertEqual(len(case_ids), len(cases))


if __name__ == "__main__":
    unittest.main()
