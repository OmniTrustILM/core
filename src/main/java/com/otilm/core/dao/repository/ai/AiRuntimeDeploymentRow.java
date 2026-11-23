package com.otilm.core.dao.repository.ai;

/** Exact configured native deployment projection; loading it is not observation or admission. */
public interface AiRuntimeDeploymentRow {
    long getVersion();

    String getImageDigest();

    String getCluster();

    String getNamespaceName();

    String getNamespaceUid();

    String getServiceAccountName();

    String getServiceAccountUid();

    String getTemplateDigest();

    String getRuntimeClass();
}
