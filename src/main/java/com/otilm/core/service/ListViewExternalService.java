package com.otilm.core.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.listview.ListViewDto;
import com.otilm.api.model.core.listview.ListViewRequestDto;
import com.otilm.api.model.core.listview.ListViewUpdateRequestDto;
import java.util.List;

/**
 * Saved list views of the authenticated user. Every operation is scoped to that user: a view of another user is not
 * visible here and is not addressable by uuid either.
 */
public interface ListViewExternalService {

    List<ListViewDto> listViews(Resource resource);

    ListViewDto createView(ListViewRequestDto request) throws AlreadyExistException;

    ListViewDto editView(String uuid, ListViewUpdateRequestDto request) throws NotFoundException, AlreadyExistException;

    void deleteView(String uuid) throws NotFoundException;
}
