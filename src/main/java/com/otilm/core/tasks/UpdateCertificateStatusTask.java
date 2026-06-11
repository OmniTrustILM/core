package com.otilm.core.tasks;

import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import com.otilm.core.dao.repository.acme.AcmeNonceRepository;
import com.otilm.core.model.ScheduledTaskResult;
import com.otilm.core.service.ApprovalInternalService;
import com.otilm.core.service.CertificateService;
import jakarta.transaction.Transactional;
import lombok.NoArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
@NoArgsConstructor
@Transactional
public class UpdateCertificateStatusTask implements ScheduledJobTask {

    private static final String JOB_NAME = "updateCertificateStatusJob";
    private static final String CRON_EXPRESSION = "0 0 * ? * *";
    private static final Logger logger = LoggerFactory.getLogger(UpdateCertificateStatusTask.class);

    private ApprovalInternalService approvalService;
    private CertificateService certificateService;
    private AcmeNonceRepository acmeNonceRepository;

    public String getDefaultJobName() {
        return JOB_NAME;
    }

    public String getDefaultCronExpression() {
        return CRON_EXPRESSION;
    }

    public boolean isDefaultOneTimeJob() {
        return false;
    }

    public String getJobClassName() {
        return this.getClass().getName();
    }

    public boolean isSystemJob() {
        return true;
    }

    public ScheduledTaskResult performJob(final ScheduledJobInfo scheduledJobInfo, final Object taskData) {
        int certificatesToValidate = certificateService.updateCertificatesStatusScheduled();
        int expiredApprovals = approvalService.checkApprovalsExpiration();
        int expiringCertificates = certificateService.handleExpiringCertificates();

        String message = "Queued %s certificates for status update.".formatted(certificatesToValidate);
        if (expiredApprovals > 0) {
            message += " Expired %d approval(s).".formatted(expiredApprovals);
        }
        if (expiringCertificates > 0) {
            message += " Handled %d expiring certificates.".formatted(expiringCertificates);
        }

        // clean up of ACME nonces
        Long deletedAcmeNonces = acmeNonceRepository.deleteByExpiresBefore(new Date());
        if (deletedAcmeNonces > 0) {
            message += " Deleted %d expired ACME nonces.".formatted(deletedAcmeNonces);
        }

        logger.debug("UpdateCertificateStatusTask completed: {}", message);

        return new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, message);
    }

    // SETTERs

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setApprovalService(ApprovalInternalService approvalService) {
        this.approvalService = approvalService;
    }

    @Autowired
    public void setAcmeNonceRepository(AcmeNonceRepository acmeNonceRepository) {
        this.acmeNonceRepository = acmeNonceRepository;
    }
}
