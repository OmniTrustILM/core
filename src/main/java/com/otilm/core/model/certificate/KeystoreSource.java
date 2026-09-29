package com.otilm.core.model.certificate;

import java.util.List;
import java.util.UUID;

/**
 * What a keystore download reads from the inventory, before its key is exported.
 *
 * @param certificateUuid the certificate
 * @param commonName the certificate's common name, which names the file
 * @param keyUuid the certificate's key
 * @param keyName the key's name
 * @param privateItemUuid the key's private key item
 * @param leaf the certificate's DER
 * @param issuers the DER of the certificate's issuers, nearest first, without a trust anchor
 */
// S6218: nothing compares, hashes or prints a source; it only carries what the download read.
@SuppressWarnings("java:S6218")
public record KeystoreSource(UUID certificateUuid, String commonName, UUID keyUuid, String keyName,
        UUID privateItemUuid, byte[] leaf, List<byte[]> issuers) {
}
