-- The repair of rows the previous behaviour left behind is a separate migration from the columns it follows,
-- so that each runs in its own transaction. Merged into one, the transaction would still hold the exclusive
-- lock the column additions take on acme_challenge while waiting for the row locks below, and an instance of
-- the previous version that holds one of those rows and then reads a challenge would deadlock the start-up.
-- Until a failed challenge invalidated its authorization and order, a failure left both pending behind the
-- challenge that recorded it. Such an authorization can never settle: the challenge is final and is not
-- validated again, and once the authorization expires it is refused rather than reported as invalid. These
-- rows are settled the way a failure is recorded now. An order that has requested or received a certificate
-- keeps its status, because the certificate exists regardless of how the order reached that state.
-- Share row exclusive keeps concurrent writers out while the repair runs without blocking readers. A request
-- that read one of these rows before the repair and writes it back afterwards still wins that write; an
-- exclusive lock would prevent it, but a request holding its read locks across a challenge validation
-- could then deadlock against the migration and fail the start-up.
LOCK TABLE acme_authorization, acme_order, acme_account IN SHARE ROW EXCLUSIVE MODE;

UPDATE acme_authorization a
SET status = 'INVALID', i_upd = CURRENT_TIMESTAMP
WHERE a.status = 'PENDING'
  AND EXISTS (SELECT 1 FROM acme_challenge c WHERE c.authorization_uuid = a.uuid AND c.status = 'INVALID');

-- The failed-order count of an account is kept as orders fail, and orders already invalid are never counted
-- again, so the orders settled here are counted now.
WITH settled AS (
    UPDATE acme_order o
    SET status = 'INVALID', i_upd = CURRENT_TIMESTAMP
    WHERE o.status IN ('PENDING', 'READY')
      AND o.certificate_ref IS NULL
      AND EXISTS (SELECT 1 FROM acme_authorization a WHERE a.order_uuid = o.uuid AND a.status = 'INVALID')
    RETURNING o.account_uuid
)
UPDATE acme_account acc
SET failed_orders = acc.failed_orders + counted.orders, i_upd = CURRENT_TIMESTAMP
FROM (SELECT account_uuid, COUNT(*) AS orders FROM settled GROUP BY account_uuid) counted
WHERE acc.uuid = counted.account_uuid;
