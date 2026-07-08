package com.otilm.core.certificate.request;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.model.request.CertificateRequest;
import com.otilm.core.service.RaProfileCertificateRequestAttributeService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.security.cert.CertificateException;
import java.util.List;

/**
 * Single reuse seam for validating a parsed protocol request (PKCS#10 or CRMF) against the resolved
 * request-attribute set.
 *
 * <p><b>What it does:</b> resolves the request-attribute set and the effective strictness via the
 * request-attribute service, then runs {@link CertificateRequestContentValidator}.
 *
 * <p><b>Failure shaping:</b> a strict policy violation throws {@link RequestAttributePolicyViolationException}.
 * That is a client fault; protocol adapters catch it and shape it into their native error.
 */
@Slf4j
@Component
public class ProtocolRequestAttributeValidator {

    private final RaProfileCertificateRequestAttributeService requestAttributeService;

    public ProtocolRequestAttributeValidator(RaProfileCertificateRequestAttributeService requestAttributeService) {
        this.requestAttributeService = requestAttributeService;
    }

    public void validate(CertificateRequest request, RaProfile raProfile) throws CertificateException {
        if (raProfile == null) {
            return;
        }
        List<BaseAttribute> definitions = resolveDefinitions(raProfile);
        if (definitions.isEmpty()) {
            return;
        }
        boolean strict = requestAttributeService.resolveExternalCsrValidationStrict(raProfile);
        reportResult(runKernel(definitions, request, raProfile, strict), raProfile);
    }

    /**
     * Resolves the request-attribute set. A strict availability failure is a server-side inability
     * (not a client fault), so it surfaces as {@link CertificateException} — adapters classify it as
     * an issuance failure ("unable to issue"), never a policy violation.
     */
    private List<BaseAttribute> resolveDefinitions(RaProfile raProfile) throws CertificateException {
        try {
            List<BaseAttribute> definitions = requestAttributeService.resolveIssueAttributeSet(raProfile);
            return definitions == null ? List.of() : definitions;
        } catch (ConnectorException | NotFoundException e) {
            if (requestAttributeService.resolveExternalCsrValidationStrict(raProfile)) {
                String reason = e instanceof NotFoundException
                        ? "the request-attribute set is not configured on the authority connector"
                        : "the authority connector is unavailable";
                throw new CertificateException(
                        "Request-attribute set is unavailable; strict RA profile '%s' cannot validate the request (%s)"
                                .formatted(raProfile.getName(), reason), e);
            }
            log.warn("Could not resolve request-attribute set (RA profile {}); lenient validation skipped", raProfile.getName(), e);
            return List.of();
        }
    }

    /**
     * Parses the request and runs {@link CertificateRequestContentValidator}.
     */
    private RequestAttributeValidationResult runKernel(List<BaseAttribute> definitions, CertificateRequest request,
                                                       RaProfile raProfile, boolean strict) {
        try {
            ParsedRequestContent parsed = X509RequestContentParser.parse(request);
            // Whitelist enforcement is tied to strict mode, so lenient mode does NOT run the whitelist check.
            return CertificateRequestContentValidator.validate(definitions, parsed, new RequestAttributePolicy(strict, strict));
        } catch (RuntimeException e) {
            log.warn("Certificate request could not be processed for validation (RA profile {})", raProfile.getName(), e);
            String msg = "Certificate request could not be processed for validation";
            throw new RequestAttributePolicyViolationException(msg, List.of(msg));
        }
    }

    private void reportResult(RequestAttributeValidationResult result, RaProfile raProfile) {
        if (!result.getWarnings().isEmpty()) {
            log.warn("Request-attribute validation (lenient) RA profile {}: {}", raProfile.getName(), result.getWarnings());
        }
        if (result.hasErrors()) {
            List<String> errors = result.getErrors();
            throw new RequestAttributePolicyViolationException(
                    "Certificate request does not satisfy the request-attribute policy of RA profile '%s': %s"
                            .formatted(raProfile.getName(), String.join("; ", errors)),
                    errors);
        }
    }
}
