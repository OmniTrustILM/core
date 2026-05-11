package com.czertainly.core.service.cmp.message;

import com.czertainly.api.model.core.cmp.CmpTransactionState;
import com.czertainly.core.dao.entity.cmp.CmpProfile;
import com.czertainly.core.dao.entity.cmp.CmpTransaction;
import com.czertainly.core.dao.repository.cmp.CmpTransactionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Component
public class CmpTransactionService {

    private CmpTransactionRepository cmpTransactionRepository;

    @Autowired
    private void setCmpTransactionRepository(CmpTransactionRepository cmpTransactionRepository) {
        this.cmpTransactionRepository = cmpTransactionRepository;
    }

    public void save(CmpTransaction transaction) {
        this.cmpTransactionRepository.save(transaction);
    }

    /**
     * List of transactions for given transactionId (even if current version of cmp czertainly
     * works with one request per transactionId).
     *
     * <p>List is prepare for future behaviour of CMP protocol (ir,cr,kur allows to process list of requests). It means
     * the given transactionId can keep relation to many request subjects (certificates).</p>
     *
     * <p>There's a next solution to move m:n relationship to another table (with removing certificate
     * column in {@link CmpTransactionService}) with list of {@link com.czertainly.core.dao.entity.Certificate}</p>
     *
     * @param transactionId unique identifier of transaction
     * @return list of transactions
     */
    public List<CmpTransaction> findByTransactionId(String transactionId) {
        return cmpTransactionRepository.findByTransactionId(transactionId);
    }

    /**
     * Helper to create {@link CmpTransaction} entity
     *
     * @param transactionId   unique identifier of transaction
     * @param cmpProfile      CMP profile
     * @param certificateUuid unique identifier of certificate
     * @param state           state of transaction
     * @return new instance of {@link CmpTransaction}
     */
    public CmpTransaction createTransactionEntity(String transactionId, CmpProfile cmpProfile,
                                                  String certificateUuid, CmpTransactionState state) {
        return createTransactionEntity(transactionId, cmpProfile, certificateUuid, state, null);
    }

    /**
     * Helper to create {@link CmpTransaction} entity with the original request body type
     * recorded so a subsequent pollReq response can be built with the matching body type.
     *
     * @param originalRequestBodyType BouncyCastle {@code PKIBody.TYPE_*} integer of the
     *                                originating request (ir / cr / kur / rr); may be {@code null}
     *                                for transactions where the original type is unknown
     */
    public CmpTransaction createTransactionEntity(String transactionId, CmpProfile cmpProfile,
                                                  String certificateUuid, CmpTransactionState state,
                                                  Integer originalRequestBodyType) {
        CmpTransaction cmpTransaction = new CmpTransaction();
        cmpTransaction.setTransactionId(transactionId);
        cmpTransaction.setCmpProfile(cmpProfile);
        cmpTransaction.setCertificateUuid(UUID.fromString(certificateUuid));
        cmpTransaction.setState(state);
        cmpTransaction.setOriginalRequestBodyType(originalRequestBodyType);
        return cmpTransaction;
    }

    /**
     * Find transaction by transactionId and fingerprint from related certificate
     *
     * @param transactionId unique identifier of transaction
     * @param fingerprint   unique identifier of certificate
     * @return a concrete transaction (fingerprints must be unique in given table)
     */
    public Optional<CmpTransaction> findByTransactionIdAndFingerprint(String transactionId, String fingerprint) {
        return cmpTransactionRepository.findByTransactionIdAndFingerprint(transactionId, fingerprint);
    }

    /**
     * Find transaction by transactionId and serial number from related certificate
     *
     * @param transactionId unique identifier of transaction
     * @param serialNumber  unique identifier of certificate
     * @return a concrete transaction (serial numbers must be unique in given table)
     */
    public Optional<CmpTransaction> findByTransactionIdAndCertificateSerialNumber(String transactionId, String serialNumber) {
        return cmpTransactionRepository.findByTransactionIdAndSerialNumber(transactionId, serialNumber);
    }
}
