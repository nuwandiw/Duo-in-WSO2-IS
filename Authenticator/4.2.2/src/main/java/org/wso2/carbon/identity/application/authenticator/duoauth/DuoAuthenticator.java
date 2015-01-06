/*
 *  Copyright (c) 2005-2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.application.authenticator.duoauth;

import com.duosecurity.client.Http;
import com.duosecurity.duoweb.DuoWeb;
import com.duosecurity.duoweb.DuoWebException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authenticator.duoauth.internal.DuoAuthenticatorServiceComponent;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Mobile based 2nd factor Local Authenticator
 */
public class DuoAuthenticator extends AbstractApplicationAuthenticator
        implements LocalApplicationAuthenticator {

    private static final long serialVersionUID = 4438354156955223654L;

    private static Log log = LogFactory.getLog(DuoAuthenticator.class);

    private String AKEY;

    @Override
    public boolean canHandle(HttpServletRequest request) {

        if (request.getParameter(DuoAuthenticatorConstants.SIG_RESPONSE) != null) {
            return true;
        }
        return false;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        String username = null;
        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
        AKEY = DuoAuthenticatorConstants.stringGenerator();

        for (int i = context.getSequenceConfig().getStepMap().size() - 1; i > 0; i--) {

            //Getting the last authenticated local user
            if (context.getSequenceConfig().getStepMap().get(i).getAuthenticatedUser() != null &&
                    context.getSequenceConfig().getStepMap().get(i).getAuthenticatedAutenticator()
                            .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {

                username = context.getSequenceConfig().getStepMap().get(i).getAuthenticatedUser();
                if (log.isDebugEnabled()) {
                    log.debug("username :" + username);
                }
                break;

            }
        }

        String mobile = null;

        if (username != null) {

            int tenantId = 0;
            try {

                tenantId = IdentityUtil.getTenantIdOFUser(username);
                UserRealm userRealm = DuoAuthenticatorServiceComponent.getRealmService()
                        .getTenantUserRealm(tenantId);

                username = MultitenantUtils.getTenantAwareUsername(username);

                if (userRealm != null) {

                    UserStoreManager userStoreManager = (UserStoreManager) userRealm.getUserStoreManager();

                    mobile = userStoreManager.getUserClaimValue(username,
                        DuoAuthenticatorConstants.MOBILE_CLAIM, null);

                } else {
                    throw new AuthenticationFailedException(
                            "Cannot find the user realm for the given tenant: " + tenantId);
                }
            } catch (IdentityException e) {
                if (log.isDebugEnabled()) {
                    log.debug(DuoAuthenticatorConstants.DuoErrors.ERROR_GETTING_PHONE);
                }
                throw new AuthenticationFailedException(
                        DuoAuthenticatorConstants.DuoErrors.ERROR_GETTING_PHONE, e);
            } catch (UserStoreException e) {
                if (log.isDebugEnabled()) {
                    log.debug(DuoAuthenticatorConstants.DuoErrors.ERROR_GETTING_PHONE);
                }
                throw new AuthenticationFailedException(
                        DuoAuthenticatorConstants.DuoErrors.ERROR_GETTING_PHONE, e);
            }


            if (log.isDebugEnabled()) {
                log.debug("mobile number : " + mobile);
            }

            Object result = null;
            if (mobile != null) {

                //Initiate Duo API request to get the user
                Http duoRequest = new Http(DuoAuthenticatorConstants.HTTP_GET,
                        getAuthenticatorConfig().getParameterMap().get(DuoAuthenticatorConstants.HOST),
                        DuoAuthenticatorConstants.API_USER);

                duoRequest.addParam(DuoAuthenticatorConstants.DUO_USERNAME, username);

                try {

                    duoRequest.signRequest(getAuthenticatorConfig().getParameterMap()
                            .get(DuoAuthenticatorConstants.ADMIN_IKEY), getAuthenticatorConfig()
                            .getParameterMap().get(DuoAuthenticatorConstants.ADMIN_SKEY));

                } catch (UnsupportedEncodingException e) {

                    if (log.isDebugEnabled()) {
                        log.debug(DuoAuthenticatorConstants.DuoErrors.ERROR_SIGN_REQUEST);
                    }

                    throw new AuthenticationFailedException(
                            DuoAuthenticatorConstants.DuoErrors.ERROR_SIGN_REQUEST, e);
                }


                try {
                    //Execute Duo API request
                    result = duoRequest.executeRequest();

                } catch (Exception e) {

                    if (log.isDebugEnabled()) {
                        log.debug(DuoAuthenticatorConstants.DuoErrors.ERROR_EXECUTE_REQUEST);
                    }

                    throw new AuthenticationFailedException(
                            DuoAuthenticatorConstants.DuoErrors.ERROR_EXECUTE_REQUEST, e);
                }

                if (result != null) {
                    if (log.isDebugEnabled()) {
                        log.debug(result.toString());
                    }

                    try {
                        JSONArray array = new JSONArray(result.toString());

                        if (array.length() == 0) {

                            if (log.isDebugEnabled()) {
                                log.debug(DuoAuthenticatorConstants.DuoErrors.ERROR_USER_NOT_FOUND);
                            }

                            throw new AuthenticationFailedException(
                                    DuoAuthenticatorConstants.DuoErrors.ERROR_USER_NOT_FOUND);

                        } else {
                            JSONArray phoneArray;

                            JSONObject object = array.getJSONObject(0);
                            phoneArray = (JSONArray) object.get(DuoAuthenticatorConstants.DUO_PHONES);

                            if (phoneArray.length() == 0) {

                                if (log.isDebugEnabled()) {
                                    log.debug(DuoAuthenticatorConstants.DuoErrors.ERROR_NUMBER_INVALID);
                                }

                                throw new AuthenticationFailedException(
                                        DuoAuthenticatorConstants.DuoErrors.ERROR_NUMBER_INVALID);

                            } else {
                                String number = ((JSONObject) phoneArray.get(0))
                                        .getString(DuoAuthenticatorConstants.DUO_NUMBER);

                                if (mobile.equals(number)) {

                                    String sig_request = DuoWeb.signRequest(getAuthenticatorConfig()
                                                    .getParameterMap().get(DuoAuthenticatorConstants.IKEY),
                                            getAuthenticatorConfig().getParameterMap()
                                                    .get(DuoAuthenticatorConstants.SKEY), AKEY, username);

                                    String DuoUrl = loginPage + "?" + FrameworkConstants.RequestParams.AUTHENTICATOR +
                                            "=" + getName() + ":" + FrameworkConstants.LOCAL_IDP_NAME + "&" +
                                            FrameworkConstants.RequestParams.TYPE + "=" +
                                            DuoAuthenticatorConstants.RequestParams.DUO + "&" +
                                            DuoAuthenticatorConstants.RequestParams.SIG_REQUEST + "=" +
                                            sig_request + "&" + FrameworkConstants.SESSION_DATA_KEY + "=" +
                                            context.getContextIdentifier() + "&" +
                                            DuoAuthenticatorConstants.RequestParams.DUO_HOST + "=" +
                                            getAuthenticatorConfig().getParameterMap()
                                                    .get(DuoAuthenticatorConstants.HOST);


                                    try {
                                        //Redirect to Duo Authentication page
                                        response.sendRedirect(response.encodeRedirectURL(DuoUrl));
                                    } catch (IOException e) {

                                        if (log.isDebugEnabled()) {
                                            log.debug(DuoAuthenticatorConstants.DuoErrors.ERROR_REDIRECTING);
                                        }

                                        throw new AuthenticationFailedException(
                                                DuoAuthenticatorConstants.DuoErrors.ERROR_REDIRECTING, e);
                                    }


                                } else {

                                    if (log.isDebugEnabled()) {
                                        log.debug(DuoAuthenticatorConstants.DuoErrors.ERROR_NUMBER_MISMATCH);
                                    }

                                    throw new AuthenticationFailedException(
                                            DuoAuthenticatorConstants.DuoErrors.ERROR_NUMBER_MISMATCH);
                                }
                            }

                        }
                    } catch (JSONException e) {

                        if (log.isDebugEnabled()) {
                            log.debug(DuoAuthenticatorConstants.DuoErrors.ERROR_JSON);
                        }

                        throw new AuthenticationFailedException(
                                DuoAuthenticatorConstants.DuoErrors.ERROR_JSON, e);
                    }

                }

            } else {

                if (log.isDebugEnabled()) {
                    log.debug(DuoAuthenticatorConstants.DuoErrors.ERROR_NUMBER_NOT_FOUND);
                }

                throw new AuthenticationFailedException(
                        DuoAuthenticatorConstants.DuoErrors.ERROR_NUMBER_NOT_FOUND);
            }
        } else {

            if (log.isDebugEnabled()) {
                log.debug("No local user found");
            }

            throw new AuthenticationFailedException("Duo authenticator failed to initialize");
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        String username = null;

        try {
            username = DuoWeb.verifyResponse(getAuthenticatorConfig().getParameterMap()
                    .get(DuoAuthenticatorConstants.IKEY), getAuthenticatorConfig().getParameterMap()
                    .get(DuoAuthenticatorConstants.SKEY), AKEY, request
                    .getParameter(DuoAuthenticatorConstants.SIG_RESPONSE));

            if (log.isDebugEnabled()) {
                log.debug("Authenticated user: " + username);
            }

        } catch (DuoWebException e) {
            if (log.isDebugEnabled()) {
                log.debug(DuoAuthenticatorConstants.DuoErrors.ERROR_VERIFY_USER);
            }

            throw new AuthenticationFailedException(
                    DuoAuthenticatorConstants.DuoErrors.ERROR_VERIFY_USER, e);

        } catch (NoSuchAlgorithmException e) {
            if (log.isDebugEnabled()) {
                log.debug(DuoAuthenticatorConstants.DuoErrors.ERROR_VERIFY_USER);
            }

            throw new AuthenticationFailedException(
                    DuoAuthenticatorConstants.DuoErrors.ERROR_VERIFY_USER, e);

        } catch (InvalidKeyException e) {
            if (log.isDebugEnabled()) {
                log.debug(DuoAuthenticatorConstants.DuoErrors.ERROR_VERIFY_USER);
            }

            throw new AuthenticationFailedException(
                    DuoAuthenticatorConstants.DuoErrors.ERROR_VERIFY_USER, e);

        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug(DuoAuthenticatorConstants.DuoErrors.ERROR_VERIFY_USER);
            }

            throw new AuthenticationFailedException(
                    DuoAuthenticatorConstants.DuoErrors.ERROR_VERIFY_USER, e);
        }

        context.setSubject(username);
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        return request.getParameter(FrameworkConstants.SESSION_DATA_KEY);
    }

    @Override
    public String getFriendlyName() {
        return DuoAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {
        return DuoAuthenticatorConstants.AUTHENTICATOR_NAME;
    }
}
