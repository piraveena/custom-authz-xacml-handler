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

package org.wso2.carbon.identity.application.authz.custom.xacml.handler.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.PostAuthenticationHandler;
import org.wso2.carbon.identity.application.authz.custom.xacml.handler.CustomXACMLBasedAuthorizationHandler;
import org.wso2.carbon.identity.entitlement.EntitlementService;

/**
 * @scr.component name="org.wso2.carbon.identity.application.authz.custom.xacml.handler.internal.AppCustomAuthzServiceComponent"
 * immediate="true"
 * @scr.reference name="identity.entitlement.service"
 * interface="org.wso2.carbon.identity.entitlement.EntitlementService"cardinality="1..1"
 * policy="dynamic" bind="setEntitlementService" unbind="unsetEntitlementService"
 */
public class AppCustomAuthzServiceComponent {

    private static final Log log = LogFactory.getLog(AppCustomAuthzServiceComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {

        try {

            CustomXACMLBasedAuthorizationHandler customAuthorizationHandler = new CustomXACMLBasedAuthorizationHandler();
            ctxt.getBundleContext().registerService(PostAuthenticationHandler.class.getName(),
                    customAuthorizationHandler, null);
            if (log.isDebugEnabled()) {
                log.debug("Custom Application XACML authorization handler bundle is activated");
            }
        } catch (Throwable throwable) {
            log.error("Error while starting identity applicaion authorization XACML component", throwable);
        }
    }

    protected void setEntitlementService(EntitlementService entitlementService) {

        if (log.isDebugEnabled()) {
            log.debug("EntitlementService is set in the Application Authentication Framework bundle");
        }
        AppAuthzDataholder.getInstance().setEntitlementService(entitlementService);
    }

    protected void unsetEntitlementService(EntitlementService entitlementService) {

        if (log.isDebugEnabled()) {
            log.debug("EntitlementService is unset in the Application Authentication Framework bundle");
        }
        AppAuthzDataholder.getInstance().setEntitlementService(null);
    }

}

