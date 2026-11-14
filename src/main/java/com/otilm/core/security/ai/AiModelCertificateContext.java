package com.otilm.core.security.ai;

import com.otilm.core.aop.TraceMetadataOnly;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateExternalService;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import com.otilm.core.service.handler.StoredCertificateHealth;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/** Reads current authorized observations from a Core-pinned actor, model and retained certificate scope. */
@Component
@TraceMetadataOnly
public class AiModelCertificateContext {
    private static final Logger LOG = LoggerFactory.getLogger(AiModelCertificateContext.class);
    private final AiModelUseAuthorization models;
    private final AiReadInvocation invocation;
    private final CertificateExternalService certificates;

    public AiModelCertificateContext(AiModelUseAuthorization models, AiReadInvocation invocation,
            CertificateExternalService certificates) {
        this.models = Objects.requireNonNull(models);
        this.invocation = Objects.requireNonNull(invocation);
        this.certificates = Objects.requireNonNull(certificates);
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public List<StoredCertificateHealth> read(UUID actor, UUID model, CertificateReadScope scope,
            AiRuntimeOperationBudget budget) {
        UUID correlation = UUID.randomUUID();
        try {
            Objects.requireNonNull(actor);
            Objects.requireNonNull(model);
            Objects.requireNonNull(scope);
            budget.remaining();
            models.requireUse(actor, model, budget);
            var result = invocation.call(actor, scope, budget.remaining(), () -> {
                var rows = new ArrayList<StoredCertificateHealth>();
                for (UUID certificate : scope.certificateUuids().stream().sorted().toList()) {
                    budget.remaining();
                    var row = certificates
                            .getStoredCertificateHealth(SecuredParentUUID.fromUUID(scope.raProfileUuid()),
                                    SecuredUUID.fromUUID(certificate));
                    budget.remaining();
                    if (row == null || !certificate.equals(row.certificateUuid())
                            || !scope.raProfileUuid().equals(row.raProfileUuid())) {
                        throw denied();
                    }
                    rows.add(row);
                }
                return List.copyOf(rows);
            });
            budget.remaining();
            LOG.debug("AI model context operation=certificate-read code=AUTHORIZED correlation={}", correlation);
            return result;
        } catch (Exception failure) {
            LOG.debug("AI model context operation=certificate-read code=DENIED correlation={}", correlation);
            throw denied();
        }
    }

    private static AccessDeniedException denied() {
        return new AccessDeniedException("Model certificate context unavailable");
    }
}
