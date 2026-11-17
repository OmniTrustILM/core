-- A certificate has one protocol association: Certificate.protocolAssociation maps it one-to-one, and a certificate
-- with a second row fails to load. Completing a registration again after a refused approval added such a row. The
-- table records no time, so of each certificate's rows the physically last one (the highest ctid), most likely its
-- latest, is kept.
DELETE FROM certificate_protocol_association earlier
    USING certificate_protocol_association later
    WHERE later.certificate_uuid = earlier.certificate_uuid
      AND later.ctid > earlier.ctid;

ALTER TABLE certificate_protocol_association
    ADD CONSTRAINT uq_certificate_protocol_association_certificate UNIQUE (certificate_uuid);
