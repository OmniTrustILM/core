-- Deleting a notification instance kept its attribute values.
-- A secret that one of them pointed at could no longer be deleted.
DELETE FROM "attribute_content_2_object" AS "mapping"
 WHERE "mapping"."object_type" = 'NOTIFICATION_INSTANCE'
   AND NOT EXISTS (SELECT 1
                     FROM "notification_instance_reference" AS "instance"
                    WHERE "instance"."uuid" = "mapping"."object_uuid");
