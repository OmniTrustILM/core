-- The unroutable tier is no longer inventoried: a component with no routable asset type is reported as an ingest
-- skip and stored as no row, so the rows that tier produced go. Nothing served them (ServedAssetType hides the type),
-- and no rule evaluates them any more. Their source links cascade; a reference that pointed at one is set to null.
DELETE FROM "crypto_asset" WHERE "asset_type" = 'UNROUTABLE';

-- The rule set changed: every applicable rule is evaluated and the weakest decides, the symmetric floor is 256 bits,
-- HAWK reads broken, a KDF/DRBG/MAC/XOF primitive takes no key-size rule, and a parameter set the registry does not
-- enumerate for its family is refused. Advancing input_revision re-offers every row to the sweep, which restamps it.
UPDATE "crypto_asset" SET "input_revision" = "input_revision" + 1;
