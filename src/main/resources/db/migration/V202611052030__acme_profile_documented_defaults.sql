-- An ACME profile created without an order validity or a retry interval was given the two defaults the wrong way round:
-- an order validity of 30 seconds and a retry interval of 36000 seconds. A profile that still holds exactly that pair
-- gets the documented defaults instead.
UPDATE acme_profile
SET validity = 36000, retry_interval = 30
WHERE validity = 30 AND retry_interval = 36000;
