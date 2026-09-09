package com.otilm.core.certificate.request;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.model.request.CertificateRequest;
import com.otilm.core.service.RaProfileCertificateRequestAttributeService;
import java.security.cert.CertificateException;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Single reuse seam for validating a parsed protocol request (PKCS#10 or CRMF) against the resolved request-attribute
 * set.
 *
 * <p>
 * <b>What it does:</b> resolves the request-attribute set and the effective strictness via the request-attribute
 * service, then runs {@link CertificateRequestContentValidator} and returns the warnings it raised.
 *
 * <p>
 * <b>Failure shaping:</b> a strict policy violation throws {@link RequestAttributePolicyViolationException}. That is a
 * client fault; protocol adapters catch it and shape it into their native error.
 */
@Slf4j
@Component
public class ProtocolRequestAttributeValidator {

    private final RaProfileCertificateRequestAttributeService requestAttributeService;

    public ProtocolRequestAttributeValidator(RaProfileCertificateRequestAttributeService requestAttributeService) {
        this.requestAttributeService = requestAttributeService;
    }

    public List<String> validate(CertificateRequest request, RaProfile raProfile) throws CertificateException {
        if (raProfile == null) {
            return List.of();
        }
        ResolvedSet resolved = resolveDefinitions(raProfile);
        if (resolved.unavailableReason() != null) {
            // Lenient fails open, so without this an empty warning list would mean both "checked, nothing found"
            // and "never checked" — and an operator reading the empty list would take it as licence to switch the
            // profile to strict.
            String warning = ("Request-attribute validation could not be performed for RA profile '%s' (%s); "
                    + "the request was accepted without checking")
                    .formatted(raProfile.getName(), resolved.unavailableReason());
            log.warn("Request-attribute validation (lenient) RA profile {}: {}", raProfile.getName(), warning);
            return List.of(warning);
        }
        List<BaseAttribute> definitions = resolved.definitions();
        if (definitions.isEmpty()) {
            return List.of();
        }
        boolean strict = requestAttributeService.resolveExternalCsrValidationStrict(raProfile);
        return reportResult(runKernel(definitions, request, raProfile, strict), raProfile);
    }

    /** The resolved request-attribute set, or the platform-authored reason it could not be resolved. */
    private record ResolvedSet(List<BaseAttribute> definitions, String unavailableReason) {
    }

    /**
     * Resolves the request-attribute set. A strict availability failure is a server-side inability (not a client
     * fault), so it surfaces as {@link CertificateException} — adapters classify it as an issuance failure ("unable to
     * issue"), never a policy violation. Lenient reports the same failure as a warning instead.
     */
    private ResolvedSet resolveDefinitions(RaProfile raProfile) throws CertificateException {
        try {
            List<BaseAttribute> definitions = requestAttributeService.resolveIssueAttributeSet(raProfile);
            return new ResolvedSet(definitions == null ? List.of() : definitions, null);
        } catch (ConnectorException | NotFoundException e) {
            String reason = e instanceof NotFoundException
                    ? "the request-attribute set is not configured on the authority connector"
                    : "the authority connector is unavailable";
            if (requestAttributeService.resolveExternalCsrValidationStrict(raProfile)) {
                log
                        .warn("Could not resolve request-attribute set (RA profile {}); strict validation cannot proceed ({})",
                                raProfile.getName(), reason, e);
                throw new CertificateException(
                        "Request-attribute set is unavailable; strict RA profile '%s' cannot validate the request (%s)"
                                .formatted(raProfile.getName(), reason),
                        e);
            }
            log
                    .warn("Could not resolve request-attribute set (RA profile {}); lenient validation skipped ({})",
                            raProfile.getName(), reason, e);
            return new ResolvedSet(List.of(), reason);
        }
    }

    /**
     * Parses the request and runs {@link CertificateRequestContentValidator}.
     */
    private RequestAttributeValidationResult runKernel(List<BaseAttribute> definitions, CertificateRequest request,
            RaProfile raProfile, boolean strict) {
        try {
            ParsedRequestContent parsed = X509RequestContentParser.parse(request);
            // The whitelist always runs; RequestAttributePolicy routes its findings to warnings when not strict.
            return CertificateRequestContentValidator
                    .validate(definitions, parsed, new RequestAttributePolicy(strict, true));
        } catch (RuntimeException e) {
            log
                    .warn("Certificate request could not be processed for validation (RA profile {})",
                            raProfile.getName(), e);
            String msg = "Certificate request could not be processed for validation";
            throw new RequestAttributePolicyViolationException(msg, List.of(msg));
        }
    }

    private List<String> reportResult(RequestAttributeValidationResult result, RaProfile raProfile) {
        if (!result.getWarnings().isEmpty()) {
            log
                    .warn("Request-attribute validation (lenient) RA profile {}: {}", raProfile.getName(),
                            result.getWarnings());
        }
        if (result.hasErrors()) {
            List<String> errors = result.getErrors();
            throw new RequestAttributePolicyViolationException(
                    "Certificate request does not satisfy the request-attribute policy of RA profile '%s': %s"
                            .formatted(raProfile.getName(), String.join("; ", errors)),
                    errors);
        }
        return result.getWarnings();
    }
}
