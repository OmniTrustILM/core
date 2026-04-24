package com.czertainly.core.service.impl;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationError;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.approval.*;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.auth.UserProfileDto;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.ApprovalRecipientRepository;
import com.czertainly.core.dao.repository.ApprovalRepository;
import com.czertainly.core.dao.repository.ApprovalStepRepository;
import com.czertainly.core.events.handlers.ApprovalClosedEventHandler;
import com.czertainly.core.events.handlers.ApprovalRequestedEventHandler;
import com.czertainly.core.messaging.jms.producers.ActionProducer;
import com.czertainly.core.messaging.jms.producers.EventProducer;
import com.czertainly.core.messaging.model.ActionMessage;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.ApprovalService;
import com.czertainly.core.util.ApprovalRecipientHelper;
import com.czertainly.core.util.AuthHelper;
import com.czertainly.core.util.RequestValidatorHelper;
import jakarta.persistence.criteria.*;
import org.apache.commons.lang3.function.TriFunction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.*;

@Service
@Transactional
public class ApprovalServiceImpl implements ApprovalService {

    private static final Logger logger = LoggerFactory.getLogger(ApprovalServiceImpl.class);

    private ApprovalRepository approvalRepository;

    private ApprovalRecipientRepository approvalRecipientRepository;

    private ApprovalStepRepository approvalStepRepository;

    private ApprovalRecipientHelper approvalRecipientHelper;

    private ActionProducer actionProducer;

    private EventProducer eventProducer;

    @Override
    @ExternalAuthorization(resource = Resource.APPROVAL, action = ResourceAction.LIST)
    public ApprovalResponseDto listApprovals(final SecurityFilter filter, final PaginationRequestDto paginationRequestDto) {
        return listOfApprovals(filter, null, paginationRequestDto);
    }

    @Override
    public ApprovalResponseDto listApprovalsByObject(final SecurityFilter securityFilter, final Resource resource, final UUID objectUuid, final PaginationRequestDto paginationRequestDto) {
        final TriFunction<Root<Approval>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause = (root, cb, cr) -> {
            final Predicate resourcePredicate = cb.equal(root.get("resource"), resource);
            final Predicate objectPredicate = cb.equal(root.get("objectUuid"), objectUuid);
            return cb.and(resourcePredicate, objectPredicate);
        };
        return listOfApprovals(securityFilter, additionalWhereClause, paginationRequestDto);
    }

    @Override
    public ApprovalResponseDto listUserApprovals(final SecurityFilter securityFilter, final boolean withHistory, final PaginationRequestDto paginationRequestDto) {
        final UserProfileDto userProfileDto = AuthHelper.getUserProfile();
        final TriFunction<Root<Approval>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause = (root, cb, cr) -> {
            final Join joinApprovalRecipient = root.join("approvalRecipients", JoinType.LEFT);
            final Predicate statusPredicate = joinApprovalRecipient.get("status").in(prepareApprovalRecipientStatuses(withHistory));
            final Predicate userUuidPredicate = cb.equal(joinApprovalRecipient.get("approvalStep").get("userUuid"), UUID.fromString(userProfileDto.getUser().getUuid()));
            final Predicate roleUuidPredicate = joinApprovalRecipient.get("approvalStep").get("roleUuid").in(userProfileDto.getRoles() == null ? List.of() : userProfileDto.getRoles().stream().map(role -> UUID.fromString(role.getUuid())).toList());
            final Predicate groupUuidPredicate = joinApprovalRecipient.get("approvalStep").get("groupUuid").in(userProfileDto.getUser().getGroups().stream().map(dto -> UUID.fromString(dto.getUuid())).toList());
            return cb.and(statusPredicate, cb.or(userUuidPredicate, roleUuidPredicate, groupUuidPredicate));
        };
        return listOfApprovals(securityFilter, additionalWhereClause, paginationRequestDto);
    }

    private List<ApprovalStatusEnum> prepareApprovalRecipientStatuses(final boolean withHistory) {
        final List<ApprovalStatusEnum> approvalStatusList = new ArrayList<>();
        if (withHistory) {
            approvalStatusList.addAll(Arrays.stream(ApprovalStatusEnum.values()).toList());
        } else {
            approvalStatusList.add(ApprovalStatusEnum.PENDING);
        }
        return approvalStatusList;
    }

    @Override
    public ApprovalDetailDto getApprovalDetail(final String uuid) throws NotFoundException {
        ApprovalDetailDto approvalDetailDto = findApprovalByUuid(uuid).mapToDetailDto();

        approvalDetailDto.setCreatorUsername(approvalRecipientHelper.getUsername(approvalDetailDto.getCreatorUuid()));
        approvalDetailDto.getApprovalSteps().forEach(approvalStep -> approvalRecipientHelper.fillApprovalDetailStepDto(approvalStep));

        return approvalDetailDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.APPROVAL, action = ResourceAction.APPROVE)
    public void approveApproval(final String uuid) throws NotFoundException {
        final Approval approval = findApprovalByUuid(uuid);
        if (approval.getStatus() != ApprovalStatusEnum.PENDING) {
            throw new ValidationException("Cannot approve approval with other than pending state. Approval UUID: " + approval.getUuid());
        }

        closeApproval(approval, ApprovalStatusEnum.APPROVED, true);
    }

    @Override
    @ExternalAuthorization(resource = Resource.APPROVAL, action = ResourceAction.APPROVE)
    public void rejectApproval(final String uuid) throws NotFoundException {
        final Approval approval = findApprovalByUuid(uuid);
        if (approval.getStatus() != ApprovalStatusEnum.PENDING) {
            throw new ValidationException("Cannot reject approval with other than pending state. Approval UUID: " + approval.getUuid());
        }

        closeApproval(approval, ApprovalStatusEnum.REJECTED, true);
    }

    @Override
    public void approveApprovalRecipient(final String approvalUuid, final UserApprovalDto userApprovalDto) throws NotFoundException {
        final ApprovalRecipient approvalRecipient = validateAndSetPendingApprovalRecipient(UUID.fromString(approvalUuid), userApprovalDto, ApprovalStatusEnum.APPROVED);
        processApprovalToTheNextStep(approvalUuid, approvalRecipient);
    }

    @Override
    public void rejectApprovalRecipient(final String approvalUuid, final UserApprovalDto userApprovalDto) throws NotFoundException {
        final Approval approval = findApprovalByUuid(approvalUuid);
        validateAndSetPendingApprovalRecipient(UUID.fromString(approvalUuid), userApprovalDto, ApprovalStatusEnum.REJECTED);
        closeApproval(approval, ApprovalStatusEnum.REJECTED, false);
    }

    @Override
    public Approval createApproval(final ApprovalProfileVersion approvalProfileVersion, final Resource resource, final ResourceAction resourceAction, final UUID objectUuid, final UUID userUuid, final Object objectData) throws NotFoundException {
        final Approval approvalCheck = approvalRepository.findByResourceAndObjectUuidAndStatus(resource, objectUuid, ApprovalStatusEnum.PENDING);
        if (approvalCheck != null) {
            throw new ValidationException(ValidationError.create("There is already pending approval for resource " + resource.getLabel() + " and object " + objectUuid));
        }

        Date now = new Date();
        logger.info("Creating new Approval for ApprovalProfileVersion {} with resources {}/{}", approvalProfileVersion.getApprovalProfile().getName(), resource.name(), resourceAction.name());
        final Approval approval = new Approval();
        approval.setApprovalProfileVersion(approvalProfileVersion);
        approval.setApprovalProfileVersionUuid(approvalProfileVersion.getUuid());
        approval.setResource(resource);
        approval.setAction(resourceAction);
        approval.setObjectUuid(objectUuid);
        approval.setCreatorUuid(userUuid);
        approval.setStatus(ApprovalStatusEnum.PENDING);
        approval.setCreatedAt(now);
        approval.setObjectData(objectData);
        if (approvalProfileVersion.getExpiry() != null && approvalProfileVersion.getExpiry() > 0) {
            approval.setExpiryAt(Date.from(now.toInstant().plus(Duration.ofHours(approvalProfileVersion.getExpiry()))));
        }

        approvalRepository.save(approval);

        processApprovalToTheNextStep(approval.getUuid().toString(), null);
        return approval;
    }

    @Override
    public int checkApprovalsExpiration() {
        List<Approval> expiredApprovals = approvalRepository.findByStatusAndExpiryAtLessThan(ApprovalStatusEnum.PENDING, new Date());
        for (Approval approval : expiredApprovals) {
            try {
                closeApproval(approval, ApprovalStatusEnum.EXPIRED, true);
            } catch (Exception e) {
                logger.error("Failed to close expired approval {} for {} {} action", approval.getUuid(), approval.getResource().getLabel(), approval.getAction().getCode());
            }
        }

        return expiredApprovals.size();
    }

    private ApprovalRecipient validateAndSetPendingApprovalRecipient(final UUID approvalUuid, final UserApprovalDto userApprovalDto, final ApprovalStatusEnum statusEnum) throws NotFoundException {
        final UserProfileDto userProfileDto = AuthHelper.getUserProfile();

        final Approval approval = findApprovalByUuid(approvalUuid.toString());
        if (approval.getCreatorUuid().toString().equals(userProfileDto.getUser().getUuid())) {
            throw new ValidationException(ValidationError.create("Approval " + approvalUuid + " can't be approved/rejected by the same user " + userProfileDto.getUser().getUsername() + " that created it."));
        }

        final List<ApprovalRecipient> approvalRecipientsByUser = approvalRecipientRepository.findByApprovalUuidAndUserUuid(approvalUuid, UUID.fromString(userProfileDto.getUser().getUuid()));
        if (approvalRecipientsByUser != null && !approvalRecipientsByUser.isEmpty()) {
            throw new ValidationException("User " + userProfileDto.getUser().getUsername() + " already made decision about the approval " + approvalUuid + ". Can't approve/reject it again.");
        }

        final List<ApprovalRecipient> approvalRecipients
                = approvalRecipientRepository.findByResponsiblePersonAndStatusAndApproval(
                UUID.fromString(userProfileDto.getUser().getUuid()),
                userProfileDto.getRoles().stream().map(role -> UUID.fromString(role.getUuid())).toList(),
                userProfileDto.getUser().getGroups().stream().map(g -> UUID.fromString(g.getUuid())).toList(),
                ApprovalStatusEnum.PENDING,
                approvalUuid);

        if (approvalRecipients == null || approvalRecipients.isEmpty()) {
            throw new NotFoundException("There is NOT expected step for current user " + userProfileDto.getUser().getUsername() + " for approval " + approvalUuid);
        } else if (approvalRecipients.size() > 1) {
            throw new ValidationException(ValidationError.create("There is more than 1 records for current user " + userProfileDto.getUser().getUsername() + " for approval " + approvalUuid));
        }

        final ApprovalRecipient approvalRecipient = approvalRecipients.get(0);
        approvalRecipient.setStatus(statusEnum);
        approvalRecipient.setClosedAt(new Date());
        approvalRecipient.setUserUuid(UUID.fromString(userProfileDto.getUser().getUuid()));
        approvalRecipient.setComment(userApprovalDto.getComment());
        approvalRecipientRepository.save(approvalRecipient);

        logger.info("User {} {} the ApprovalRecipient {}", userProfileDto.getUser().getUuid(), statusEnum.getCode(), approvalRecipient.getUuid());
        return approvalRecipient;
    }

    private void processApprovalToTheNextStep(final String approvalUuid, final ApprovalRecipient lastProcessedApprovalRecipient) throws NotFoundException {

        final List<ApprovalRecipient> approvalRecipients = approvalRecipientRepository.findApprovalRecipientsByApprovalUuidAndStatus(UUID.fromString(approvalUuid), ApprovalStatusEnum.PENDING);
        if (approvalRecipients != null && !approvalRecipients.isEmpty()) {
            throw new ValidationException(ValidationError.create("There are still exist some pending steps for Approval " + approvalUuid));
        }

        final ApprovalStep nextApprovalStep = approvalStepRepository.findNextApprovalStepForApproval(UUID.fromString(approvalUuid));
        if (nextApprovalStep != null) {
            logger.info("Creating new PENDING ApprovalRecipient for approval {}", approvalUuid);
            final ApprovalRecipient approvalRecipient = new ApprovalRecipient();
            approvalRecipient.setApprovalUuid(UUID.fromString(approvalUuid));
            approvalRecipient.setApprovalStepUuid(nextApprovalStep.getUuid());
            approvalRecipient.setApprovalStep(nextApprovalStep);
            approvalRecipient.setStatus(ApprovalStatusEnum.PENDING);
            approvalRecipient.setCreatedAt(lastProcessedApprovalRecipient != null ? lastProcessedApprovalRecipient.getCreatedAt() : new Date());
            approvalRecipientRepository.save(approvalRecipient);

            if (lastProcessedApprovalRecipient == null
                    || lastProcessedApprovalRecipient.getApprovalStep().getOrder() != nextApprovalStep.getOrder()) {

                final Approval approval = findApprovalByUuid(approvalUuid);
                eventProducer.produceMessage(ApprovalRequestedEventHandler.constructEventMessage(approval.getUuid(), nextApprovalStep.mapToDto()));
                logger.debug("Notification message about new approvals needed for the step was sent. Approval UUID: {}", approvalUuid);
            }
        } else {
            logger.info("There is no more steps and the approval can be closed as successful.");
            final Approval approval = findApprovalByUuid(approvalUuid);
            closeApproval(approval, ApprovalStatusEnum.APPROVED, false);
        }
    }

    private void closeApproval(Approval approval, ApprovalStatusEnum approvalStatus, boolean overrideFlow) {
        if (overrideFlow) {
            // close pending recipient because approval flow is overridden and going to be closed
            final List<ApprovalRecipient> approvalRecipients = approvalRecipientRepository.findApprovalRecipientsByApprovalUuidAndStatus(approval.getUuid(), ApprovalStatusEnum.PENDING);
            if (approvalRecipients == null || approvalRecipients.size() != 1) {
                throw new ValidationException(ValidationError.create("There are no or more existing pending steps for Approval " + approval.getUuid()));
            }
            final ApprovalRecipient approvalRecipient = approvalRecipients.get(0);
            approvalRecipient.setStatus(approvalStatus);
            approvalRecipient.setClosedAt(new Date());

            if (approvalStatus == ApprovalStatusEnum.EXPIRED) {
                approvalRecipient.setComment("Approval expired");
                logger.info("ApprovalRecipient {} is marked as {}", approvalRecipient.getUuid(), approvalStatus.getCode());
            } else {
                final UserProfileDto userProfileDto = AuthHelper.getUserProfile();
                approvalRecipient.setUserUuid(UUID.fromString(userProfileDto.getUser().getUuid()));
                approvalRecipient.setComment("Approval flow overridden");
                logger.info("User {} marked the ApprovalRecipient {} as {}", userProfileDto.getUser().getUsername(), approvalRecipient.getUuid(), approvalStatus.getCode());
            }
            approvalRecipientRepository.save(approvalRecipient);
        }

        // change approval status
        logger.info("Changing Approval {} status up to {}", approval.getUuid(), approvalStatus.getCode());
        approval.setStatus(approvalStatus);
        approval.setClosedAt(new Date());
        approvalRepository.save(approval);

        // if approved, perform action linked with approval
        final ActionMessage actionMessage = new ActionMessage();
        actionMessage.setUserUuid(approval.getCreatorUuid());
        actionMessage.setApprovalUuid(approval.getUuid());
        actionMessage.setApprovalStatus(approvalStatus);
        actionMessage.setData(approval.getObjectData());
        actionMessage.setResourceUuid(approval.getObjectUuid());
        actionMessage.setResource(approval.getResource());
        actionMessage.setResourceAction(approval.getAction());
        actionProducer.produceMessage(actionMessage);

        // send event of approval closed
        eventProducer.produceMessage(ApprovalClosedEventHandler.constructEventMessage(approval.getUuid()));
    }

    private Approval findApprovalByUuid(final String uuid) throws NotFoundException {
        final Optional<Approval> approvalOptional = approvalRepository.findByUuid(SecuredUUID.fromString(uuid));
        if (approvalOptional.isPresent()) {
            return approvalOptional.get();
        }
        throw new NotFoundException("Unable to find approval with UUID: {}", uuid);
    }

    private ApprovalResponseDto listOfApprovals(final SecurityFilter securityFilter, final TriFunction<Root<Approval>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause, final PaginationRequestDto paginationRequestDto) {
        RequestValidatorHelper.revalidatePaginationRequestDto(paginationRequestDto);
        final Pageable pageable = PageRequest.of(paginationRequestDto.getPageNumber() - 1, paginationRequestDto.getItemsPerPage());
        final List<Approval> approvalList = approvalRepository.findUsingSecurityFilter(securityFilter, List.of("approvalProfileVersion"), additionalWhereClause, pageable, (root, cb) -> cb.desc(root.get("createdAt")));
        final Long maxItems = approvalRepository.countUsingSecurityFilter(securityFilter, additionalWhereClause);
        final ApprovalResponseDto responseDto = new ApprovalResponseDto();
        responseDto.setApprovals(approvalList.stream()
                .map(a -> {
                    ApprovalDto dto = a.mapToDto();
                    dto.setCreatorUsername(this.approvalRecipientHelper.getUsername(dto.getCreatorUuid()));
                    return dto;
                }).toList());
        responseDto.setItemsPerPage(paginationRequestDto.getItemsPerPage());
        responseDto.setPageNumber(paginationRequestDto.getPageNumber());
        responseDto.setTotalItems(maxItems);
        responseDto.setTotalPages((int) Math.ceil((double) maxItems / paginationRequestDto.getItemsPerPage()));
        return responseDto;
    }

    // SETTERs

    @Autowired
    public void setApprovalRepository(ApprovalRepository approvalRepository) {
        this.approvalRepository = approvalRepository;
    }

    @Autowired
    public void setApprovalRecipientRepository(ApprovalRecipientRepository approvalRecipientRepository) {
        this.approvalRecipientRepository = approvalRecipientRepository;
    }

    @Autowired
    public void setApprovalStepRepository(ApprovalStepRepository approvalStepRepository) {
        this.approvalStepRepository = approvalStepRepository;
    }

    @Autowired
    public void setActionProducer(ActionProducer actionProducer) {
        this.actionProducer = actionProducer;
    }

    @Autowired
    public void setEventProducer(EventProducer eventProducer) {
        this.eventProducer = eventProducer;
    }

    @Autowired
    public void setApprovalRecipientHelper(ApprovalRecipientHelper approvalRecipientHelper) {
        this.approvalRecipientHelper = approvalRecipientHelper;
    }
}
