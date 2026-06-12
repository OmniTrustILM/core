package com.otilm.core.service.cmp;

import com.otilm.api.interfaces.core.cmp.error.CmpBaseException;
import org.springframework.http.ResponseEntity;

public interface CmpService {

    ResponseEntity<byte[]> handlePost(String cmpProfileName, byte[] request) throws CmpBaseException;

}
