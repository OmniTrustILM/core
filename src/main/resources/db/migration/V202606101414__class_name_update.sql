UPDATE scheduled_job SET job_class_name = REPLACE(job_class_name, 'com.czertainly.core.tasks', 'com.otilm.core.tasks');

UPDATE spring_session_attributes SET attribute_bytes = REPLACE(attribute_bytes::text, 'com.czertainly.core', 'com.otilm.core')::jsonb;
