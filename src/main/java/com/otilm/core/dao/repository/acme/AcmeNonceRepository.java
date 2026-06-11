package com.otilm.core.dao.repository.acme;

import com.otilm.core.dao.entity.acme.AcmeNonce;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.Optional;

@Repository
public interface AcmeNonceRepository extends SecurityFilterRepository<AcmeNonce, Long> {
    Optional<AcmeNonce> findByNonce(String nonce);

     Long deleteByExpiresBefore(Date expires);
}
