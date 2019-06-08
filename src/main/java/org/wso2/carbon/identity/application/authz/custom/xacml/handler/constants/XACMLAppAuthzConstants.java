package org.wso2.carbon.identity.application.authz.custom.xacml.handler.constants;

/**
 * This class contains the constants required for XACML based application authorization handler
 */
public class XACMLAppAuthzConstants {

    public static final String SP_CATEGORY = "http://wso2.org/identity/sp";
    public static final String USER_CATEGORY = "http://wso2.org/identity/user";
    public static final String AUTH_CATEGORY = "http://wso2.org/identity/auth";
    public static final String AUTH_CONTEXT_PROPERTY_CATEGORY = "http://wso2.org/identity/auth-context-property";
    public static final String AUTH_CONTEXT_REQ_PARAM_CATEGORY = "http://wso2.org/identity/auth-context-request-param";
    public static final String AUTH_CONTEXT_REQ_HEADER_CATEGORY = "http://wso2" +
            ".org/identity/auth-context-request-header";
    public static final String ACTION_CATEGORY = "http://wso2.org/identity/identity-action";
    public static final String AUTH_ACTION_ID = ACTION_CATEGORY + "/action-name";
    public static final String AUTH_CTX_ID = AUTH_CATEGORY + "/auth-ctx-id";
    public static final String SP_NAME_ID = SP_CATEGORY + "/sp-name";
    public static final String SP_DOMAIN_ID = SP_CATEGORY + "/sp-tenant-domain";
    public static final String USERNAME_ID = USER_CATEGORY + "/username";
    public static final String USER_STORE_ID = USER_CATEGORY + "/user-store-domain";
    public static final String USER_TENANT_DOMAIN_ID = USER_CATEGORY + "/user-tenant-domain";

    public static final String INBOUND_PROTOCOL_ATTRIBUTE = AUTH_CATEGORY + "/inbound-protocol";
    public static final String CLIENT_IP_ATTRIBUTE = AUTH_CATEGORY + "/user-ip";


    private XACMLAppAuthzConstants() {

    }

}
