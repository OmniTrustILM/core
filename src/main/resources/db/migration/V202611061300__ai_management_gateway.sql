-- Independent management transport membership; no run or global activation authority.
CREATE TABLE ai_management_gateway_deployment (
 id integer PRIMARY KEY CHECK (id=1), revision bigint NOT NULL CHECK(revision>=0), configured boolean NOT NULL,
 image_digest text, cluster text, namespace_name text, namespace_uid text,
 service_account_name text, service_account_uid text, template_digest text, runtime_class text,
 CHECK (NOT configured OR (revision>0 AND image_digest IS NOT NULL AND template_digest IS NOT NULL AND image_digest ~ '^sha256:[0-9a-f]{64}$' AND cluster IS NOT NULL
 AND namespace_name IS NOT NULL AND namespace_uid IS NOT NULL AND service_account_name IS NOT NULL
 AND service_account_uid IS NOT NULL AND template_digest ~ '^sha256:[0-9a-f]{64}$' AND runtime_class IS NOT NULL))
);
INSERT INTO ai_management_gateway_deployment(id,revision,configured) VALUES(1,0,false);
CREATE TABLE ai_management_gateway_registration (
 pod_uid uuid PRIMARY KEY, deployment_revision bigint NOT NULL CHECK(deployment_revision>0),
 pod_name text NOT NULL, observation_sequence bigint NOT NULL CHECK(observation_sequence>0),
 evidence_id uuid NOT NULL, observed_at timestamptz NOT NULL, valid_until timestamptz NOT NULL,
 revoked boolean NOT NULL DEFAULT false,
 CHECK(observed_at<valid_until AND valid_until<=observed_at+interval '30 seconds')
);
