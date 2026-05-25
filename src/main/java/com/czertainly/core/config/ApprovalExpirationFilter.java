package com.czertainly.core.config;

import com.czertainly.core.service.ApprovalInternalService;
import jakarta.servlet.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import java.io.IOException;

public class ApprovalExpirationFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(ApprovalExpirationFilter.class);

    private ApprovalInternalService approvalService;

    @Autowired
    public void setApprovalService(ApprovalInternalService approvalService) {
        this.approvalService = approvalService;
    }

    @Override
    public void init(FilterConfig filterConfig) {
        SpringBeanAutowiringSupport.processInjectionBasedOnServletContext(this, filterConfig.getServletContext());
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws ServletException, IOException {
        logger.debug("Checking expired approvals");
        int expiredApprovals = approvalService.checkApprovalsExpiration();

        if (expiredApprovals > 0) {
            logger.info("Expired {} approvals", expiredApprovals);
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }

    @Override
    public void destroy() {
        Filter.super.destroy();
    }
}
