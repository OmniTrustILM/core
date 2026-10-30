package com.otilm.core.certificate.request;

import com.otilm.api.model.connector.v3.certificate.X509RequestContent;

import java.util.List;

/**
 * Result of parsing a supplied certificate request: the typed {@code content}, the SAN kinds the parser could not
 * represent ({@code unsupportedSans}, e.g. {@code x400Address} or an undecodable entry), and the structured-extension
 * items it could not name ({@code unrepresentableExtensionValues}, e.g. a key usage bit outside the nine X.509 names).
 * Both unrepresented lists must reach the whitelist check so a strict policy fails closed — the uploaded CSR is
 * forwarded to the CA verbatim, so anything invisible to validation would otherwise bypass it.
 */
public record ParsedRequestContent(X509RequestContent content, List<String> unsupportedSans,
        List<String> unrepresentableExtensionValues) {
}
