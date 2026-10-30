-- CMP-issued certificates recorded the RA Profile UUID as the protocol profile.
-- The original CMP Profile cannot be reconstructed reliably (the CMP Profile <-> RA Profile
-- binding is mutable), so the column becomes nullable and known-wrong CMP values are cleared.
ALTER TABLE certificate_protocol_association ALTER COLUMN protocol_profile_uuid DROP NOT NULL;

UPDATE certificate_protocol_association SET protocol_profile_uuid = NULL WHERE protocol = 'CMP';
