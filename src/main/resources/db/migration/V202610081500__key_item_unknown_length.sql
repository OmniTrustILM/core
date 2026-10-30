-- An unknown key length is stored as null; earlier rows stored it as a length below 1.
UPDATE "cryptographic_key_item" SET "length" = NULL WHERE "length" <= 0;
