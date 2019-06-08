/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authz.custom.xacml.handler;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.axiom.om.xpath.AXIOMXPath;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jaxen.JaxenException;
import org.wso2.balana.utils.Constants.PolicyConstants;
import org.wso2.balana.utils.exception.PolicyBuilderException;
import org.wso2.balana.utils.policy.PolicyBuilder;
import org.wso2.balana.utils.policy.dto.RequestElementDTO;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.exception.PostAuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.AbstractPostAuthnHandler;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.PostAuthnHandlerFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authz.custom.xacml.handler.constants.XACMLAppAuthzConstants;
import org.wso2.carbon.identity.application.authz.custom.xacml.handler.internal.AppAuthzDataholder;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.entitlement.EntitlementException;
import org.wso2.carbon.identity.entitlement.common.EntitlementPolicyConstants;
import org.wso2.carbon.identity.entitlement.common.dto.RequestDTO;
import org.wso2.carbon.identity.entitlement.common.dto.RowDTO;
import org.wso2.carbon.identity.entitlement.common.util.PolicyCreatorUtil;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.stream.XMLStreamException;

public class CustomXACMLBasedAuthorizationHandler extends AbstractPostAuthnHandler {

    private static final Log log = LogFactory.getLog(CustomXACMLBasedAuthorizationHandler.class);
    private static final String DECISION_XPATH = "//ns:Result/ns:Decision/text()";
    private static final String OBLIGATION_XPATH = "//ns:Result/ns:Obligations/ns:Obligation" ;
    //"/ns:AttributeAssignment/text()";

    private static final String XACML_NS = "urn:oasis:names:tc:xacml:3.0:core:schema:wd-17";
    private static final String XACML_NS_PREFIX = "ns";
    private static final String RULE_EFFECT_PERMIT = "Permit";
    private static final String RULE_EFFECT_NOT_APPLICABLE = "NotApplicable";
    public static final String ACTION_AUTHENTICATE = "authenticate";

    @Override
    public int getPriority() {

        int priority = super.getPriority();
        if (priority == -1) {
            priority = 20;
        }
        return priority;
    }

    /**
     * Executes the authorization flow
     *
     * @param request  request
     * @param response response
     * @param context  context
     */
    @Override
    public PostAuthnHandlerFlowStatus handle(HttpServletRequest request, HttpServletResponse response,
                                             AuthenticationContext context) throws PostAuthenticationFailedException {

        log.info("====================CustomXACMLBasedAuthorizationHandler");
        if (log.isDebugEnabled()) {
            log.debug("In policy authorization flow...");
        }

        if (!isAuthorizationEnabled(context) || getAuthenticatedUser(context) == null) {
            return PostAuthnHandlerFlowStatus.SUCCESS_COMPLETED;
        }
        try {
            context.addParameter(IdentityConstants.USER_IP, IdentityUtil.getClientIpAddress(request));
            FrameworkUtils.addAuthenticationContextToCache(context.getContextIdentifier(), context);

            String requestString  = createRequest(context);
            if (log.isDebugEnabled()) {
                log.debug("XACML Authorization request :\n" + requestString);
            }

            FrameworkUtils.startTenantFlow(context.getTenantDomain());
            String responseString =
                    AppAuthzDataholder.getInstance().getEntitlementService().getDecision(requestString);
            if (log.isDebugEnabled()) {
                log.debug("XACML Authorization response :\n" + responseString);
            }

            String role = getRoleFromXACMLPolicy(responseString);
            if (log.isDebugEnabled()) {
                log.debug("User role is:\n" + role);
            }

            if(StringUtils.isNotEmpty(role)) {
                // Add the claim from XACML policy as user attribute.
                setRoleAsUserAttributes(role,context);
                return PostAuthnHandlerFlowStatus.SUCCESS_COMPLETED;
            }

            return PostAuthnHandlerFlowStatus.INCOMPLETE;


        } catch (EntitlementException | FrameworkException e) {
            throw new PostAuthenticationFailedException("Authorization Failed", "Error while trying to evaluate " +
                    "authorization", e);
        } finally {
            FrameworkUtils.endTenantFlow();
        }
    }

    private Map<ClaimMapping, String> setRoleAsUserAttributes(String role, AuthenticationContext context) {

        // Get all user attributes in authentication context.
        Map<ClaimMapping, String> userAttributes =
                context.getSequenceConfig().getAuthenticatedUser().getUserAttributes();
        Map<String, String> roles = new HashMap<>();
        roles.put("http://wso2.org/claims/role", role);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Setting role %s as user role", role));
        }
        Map<ClaimMapping, String> rolesClaims = FrameworkUtils.buildClaimMappings(roles);

        // Add the role claim from XACML policy
        for (Map.Entry<ClaimMapping, String> entry : rolesClaims.entrySet()) {
            log.info(entry.getKey() + " = " + entry.getValue());
            userAttributes.put(entry.getKey(), entry.getValue());
        }

        context.getSequenceConfig().getAuthenticatedUser().setUserAttributes(userAttributes);
        return userAttributes;
    }

    private String createRequest(AuthenticationContext context) throws PostAuthenticationFailedException {

        RequestDTO requestDTO = createRequestDTO(context);
        RequestElementDTO requestElementDTO = PolicyCreatorUtil.createRequestElementDTO(requestDTO);
        String requestString;
        try {
            requestString = PolicyBuilder.getInstance().buildRequest(requestElementDTO);
        } catch (PolicyBuilderException e) {
            throw new PostAuthenticationFailedException("Authorization Failed", "Error while trying to evaluate " +
                    "authorization", e);
        }
        return requestString;

    }

    private RequestDTO createRequestDTO(AuthenticationContext context) {

        List<RowDTO> rowDTOs = new ArrayList<>();
        RowDTO actionDTO =
                createRowDTO(ACTION_AUTHENTICATE,
                        XACMLAppAuthzConstants.AUTH_ACTION_ID, XACMLAppAuthzConstants.ACTION_CATEGORY);
        RowDTO contextIdentifierDTO =
                createRowDTO(context.getContextIdentifier(),
                        XACMLAppAuthzConstants.AUTH_CTX_ID, XACMLAppAuthzConstants.AUTH_CATEGORY);
        RowDTO spNameDTO =
                createRowDTO(context.getServiceProviderName(),
                        XACMLAppAuthzConstants.SP_NAME_ID, XACMLAppAuthzConstants.SP_CATEGORY);
        RowDTO spDomainDTO =
                createRowDTO(context.getTenantDomain(),
                        XACMLAppAuthzConstants.SP_DOMAIN_ID, XACMLAppAuthzConstants.SP_CATEGORY);
        RowDTO usernameDTO =
                createRowDTO(context.getSequenceConfig().getAuthenticatedUser().getUserName(),
                        XACMLAppAuthzConstants.USERNAME_ID, XACMLAppAuthzConstants.USER_CATEGORY);
        RowDTO userStoreDomainDTO =
                createRowDTO(context.getSequenceConfig().getAuthenticatedUser().getUserStoreDomain(),
                        XACMLAppAuthzConstants.USER_STORE_ID, XACMLAppAuthzConstants.USER_CATEGORY);
        RowDTO userTenantDomainDTO =
                createRowDTO(context.getSequenceConfig().getAuthenticatedUser().getTenantDomain(),
                        XACMLAppAuthzConstants.USER_TENANT_DOMAIN_ID, XACMLAppAuthzConstants.USER_CATEGORY);
        String subject = null;
        if (context.getSequenceConfig() != null && context.getSequenceConfig().getAuthenticatedUser() != null) {
            subject = context.getSequenceConfig().getAuthenticatedUser().toString();
        }
        if (subject != null) {
            RowDTO subjectDTO =
                    createRowDTO(subject, PolicyConstants.SUBJECT_ID_DEFAULT, PolicyConstants.SUBJECT_CATEGORY_URI);
            rowDTOs.add(subjectDTO);
        }
        rowDTOs.add(actionDTO);
        rowDTOs.add(contextIdentifierDTO);
        rowDTOs.add(spNameDTO);
        rowDTOs.add(spDomainDTO);
        rowDTOs.add(usernameDTO);
        rowDTOs.add(userStoreDomainDTO);
        rowDTOs.add(userTenantDomainDTO);
        RequestDTO requestDTO = new RequestDTO();
        requestDTO.setRowDTOs(rowDTOs);
        return requestDTO;
    }

    private RowDTO createRowDTO(String resourceName, String attributeId, String categoryValue) {

        RowDTO rowDTOTenant = new RowDTO();
        rowDTOTenant.setAttributeValue(resourceName);
        rowDTOTenant.setAttributeDataType(EntitlementPolicyConstants.STRING_DATA_TYPE);
        rowDTOTenant.setAttributeId(attributeId);
        rowDTOTenant.setCategory(categoryValue);
        return rowDTOTenant;

    }

    private String getRoleFromXACMLPolicy(String xacmlResponse) throws FrameworkException {

        String role = null;

        try {
            AXIOMXPath axiomxPath = new AXIOMXPath(OBLIGATION_XPATH);
            axiomxPath.addNamespace(XACML_NS_PREFIX, XACML_NS);
            OMElement rootElement =
                    new StAXOMBuilder(new ByteArrayInputStream(xacmlResponse.getBytes(StandardCharsets.UTF_8)))
                            .getDocumentElement();
            role = getRoleString(axiomxPath.stringValueOf(rootElement));

        } catch (JaxenException | XMLStreamException e) {
            throw new FrameworkException("Exception occurred when getting decision from xacml response.", e);
        }
        return role;
    }

    private String getRoleString (String role){
        // do null check
        role = role.replace("\n",",");
        String[] roles = role.split(",");
        String roleString = "";
        for (int x=0;x<roles.length;x++) {
            if(!roles[x].isEmpty()) {
                if (x != roles.length-1) {
                    roleString += roles[x] + ",";
                } else {
                    roleString += roles[x];

                }
            }
        }
        return roleString;
    }

    private AuthenticatedUser getAuthenticatedUser(AuthenticationContext authenticationContext) {

        if (authenticationContext != null && authenticationContext.getSequenceConfig() != null) {
            return authenticationContext.getSequenceConfig().getAuthenticatedUser();
        }
        return null;
    }

    private boolean isAuthorizationEnabled(AuthenticationContext authenticationContext) {

        if (authenticationContext != null && authenticationContext.getSequenceConfig() != null &&
                authenticationContext.getSequenceConfig().getApplicationConfig() != null) {
            return authenticationContext.getSequenceConfig().getApplicationConfig().isEnableAuthorization();
        }
        return false;
    }
}
