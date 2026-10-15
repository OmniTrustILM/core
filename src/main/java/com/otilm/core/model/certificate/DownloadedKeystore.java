package com.otilm.core.model.certificate;

/**
 * A downloaded keystore.
 *
 * @param name the certificate's common name, which names the file
 * @param content the DER-encoded PKCS#12 file
 */
// S6218: nothing compares, hashes or prints a download; it only carries the file to the response.
@SuppressWarnings("java:S6218")
public record DownloadedKeystore(String name, byte[] content) {
}
