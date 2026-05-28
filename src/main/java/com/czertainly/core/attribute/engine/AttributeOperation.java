package com.czertainly.core.attribute.engine;

public class AttributeOperation {

    public static final String CERTIFICATE_ISSUE = "issue";
    public static final String CERTIFICATE_REVOKE = "revoke";
    public static final String CERTIFICATE_REQUEST_SIGN = "sign"; // legacy usage in database migration
    public static final String SIGN = "sign";
    public static final String ENCRYPT = "encrypt";
    public static final String WORKFLOW_FORMATTER = "workflowFormatter";

    private AttributeOperation() {
    }

}
