package com.czertainly.core.api.local;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.local.LocalController;
import com.otilm.api.model.client.auth.AddUserRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.auth.UserDetailDto;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.service.LocalAdminExternalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

@RestController
public class LocalControllerImpl implements LocalController {


    @Autowired
    private LocalAdminExternalService localAdminService;

    @Override
    @AuditLogged(module = Module.AUTH, resource = Resource.USER, operation = Operation.CREATE)
    public ResponseEntity<UserDetailDto> addAdmin(@RequestBody AddUserRequestDto request) throws NotFoundException, CertificateException, NoSuchAlgorithmException, AlreadyExistException, AttributeException {
        UserDetailDto userDto = localAdminService.createUser(request);

        URI location = ServletUriComponentsBuilder
                .fromCurrentRequest()
                .path("/{uuid}")
                .buildAndExpand(userDto.getUuid())
                .toUri();
        return ResponseEntity.created(location).body(userDto);
    }
}
