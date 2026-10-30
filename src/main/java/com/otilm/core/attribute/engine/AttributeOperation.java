package com.otilm.core.attribute.engine;

public class AttributeOperation {

    public static final String CERTIFICATE_ISSUE = "issue";
    public static final String CERTIFICATE_REVOKE = "revoke";
    public static final String CERTIFICATE_REGISTER = "register";
    // Rekey funnels into the renew connector operation, so rekey values persist under CERTIFICATE_RENEW too.
    public static final String CERTIFICATE_RENEW = "renew";
    public static final String CERTIFICATE_IDENTIFY = "identify";
    public static final String CERTIFICATE_REQUEST_SIGN = "sign"; // legacy usage in database migration
    public static final String SIGN = "sign";
    public static final String ENCRYPT = "encrypt";
    public static final String WORKFLOW_FORMATTING = "workflowFormatting";

    private AttributeOperation() {
    }

}
