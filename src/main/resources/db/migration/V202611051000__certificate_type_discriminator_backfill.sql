-- certificate_type becomes the discriminator of the certificate and certificate request entity hierarchies, so every
-- row needs a value. The backfill runs in batches that commit separately (see the .conf file next to this script), so
-- a large inventory is never locked or written in one transaction. Rerunning it is harmless: it only touches rows
-- that still have no type.
DO
$$
DECLARE
    batch_size CONSTANT integer := 10000;
    updated integer;
BEGIN
    LOOP
        UPDATE certificate SET certificate_type = 'X509'
        WHERE uuid IN (SELECT uuid FROM certificate WHERE certificate_type IS NULL OR certificate_type = ''
                       LIMIT batch_size);
        GET DIAGNOSTICS updated = ROW_COUNT;
        EXIT WHEN updated = 0;
        COMMIT;
    END LOOP;

    LOOP
        UPDATE certificate_request SET certificate_type = 'X509'
        WHERE uuid IN (SELECT uuid FROM certificate_request WHERE certificate_type IS NULL OR certificate_type = ''
                       LIMIT batch_size);
        GET DIAGNOSTICS updated = ROW_COUNT;
        EXIT WHEN updated = 0;
        COMMIT;
    END LOOP;
END
$$;
