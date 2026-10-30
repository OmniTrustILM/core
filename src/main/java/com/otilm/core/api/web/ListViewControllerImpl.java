package com.otilm.core.api.web;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.web.ListViewController;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.listview.ListViewDto;
import com.otilm.api.model.core.listview.ListViewRequestDto;
import com.otilm.api.model.core.listview.ListViewUpdateRequestDto;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.logging.LogResource;
import com.otilm.core.service.ListViewExternalService;
import com.otilm.core.util.converter.ResourceCodeConverter;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ListViewControllerImpl implements ListViewController {

    private ListViewExternalService listViewService;

    @InitBinder
    public void initBinder(final WebDataBinder webdataBinder) {
        webdataBinder.registerCustomEditor(Resource.class, new ResourceCodeConverter());
    }

    @Autowired
    public void setListViewService(ListViewExternalService listViewService) {
        this.listViewService = listViewService;
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.LIST_VIEW, operation = Operation.LIST)
    public List<ListViewDto> listViews(Resource resource) {
        return listViewService.listViews(resource);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.LIST_VIEW, operation = Operation.CREATE)
    public ListViewDto createView(ListViewRequestDto request) throws AlreadyExistException {
        return listViewService.createView(request);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.LIST_VIEW, operation = Operation.UPDATE)
    public ListViewDto editView(@LogResource(uuid = true) String uuid, ListViewUpdateRequestDto request)
            throws NotFoundException, AlreadyExistException {
        return listViewService.editView(uuid, request);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.LIST_VIEW, operation = Operation.DELETE)
    public void deleteView(@LogResource(uuid = true) String uuid) throws NotFoundException {
        listViewService.deleteView(uuid);
    }
}
