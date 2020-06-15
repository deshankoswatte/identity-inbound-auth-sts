/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.carbon.identity.sts.passive.custom.handler;

import org.apache.cxf.rt.security.claims.Claim;
import org.apache.cxf.rt.security.claims.ClaimCollection;
import org.apache.cxf.sts.claims.ClaimsHandler;
import org.apache.cxf.sts.claims.ClaimsParameters;
import org.apache.cxf.sts.claims.ProcessedClaim;
import org.apache.cxf.sts.claims.ProcessedClaimCollection;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A custom ClaimsHandler implementation to be used in the implementation.
 */
public class CustomClaimsHandler implements ClaimsHandler {

    private static HashMap<String, org.wso2.carbon.user.core.claim.Claim> supportedClaims = new HashMap<>();
    private HashMap<String, String> requestedClaims = new HashMap<>();

    /**
     * Create a processed claim collection using the claim values and params provided.
     *
     * @param claims     The unprocessed claims.
     * @param parameters The claim parameters.
     * @return The processed claims.
     */
    public ProcessedClaimCollection retrieveClaimValues(
            ClaimCollection claims, ClaimsParameters parameters) {

        if (claims != null && !claims.isEmpty()) {
            ProcessedClaimCollection claimCollection = new ProcessedClaimCollection();
            for (Claim requestClaim : claims) {
                ProcessedClaim claim = new ProcessedClaim();
                claim.setClaimType(requestClaim.getClaimType());
                if (supportedClaims.containsKey(requestClaim.getClaimType()) &&
                        requestedClaims.containsKey(requestClaim.getClaimType())) {
                    claim.addValue(requestedClaims.get(requestClaim.getClaimType()));
                }
                claimCollection.add(claim);
            }
            return claimCollection;
        }

        return null;
    }

    /**
     * Get the supported claim URIs.
     *
     * @return List of supported claim URIs.
     */
    public List<String> getSupportedClaimTypes() {

        List<String> supportedClaimTypes = new ArrayList<>();
        for (Map.Entry supportedClaim : supportedClaims.entrySet()) {
            supportedClaimTypes.add((String) supportedClaim.getKey());
        }

        return supportedClaimTypes;
    }

    /**
     * Set the supported claims.
     *
     * @param supportedClaims The new HashMap with the supported claims.
     */
    public static void setSupportedClaimsTypes(HashMap<String, org.wso2.carbon.user.core.claim.Claim> supportedClaims) {

        CustomClaimsHandler.supportedClaims = supportedClaims;
    }

    /**
     * Get the requested claims(Contains the URI and value).
     *
     * @return HashMap containing the requested claim URIs and values.
     */
    public HashMap<String, String> getRequestedClaims() {

        return requestedClaims;
    }

    /**
     * Set the requested claims.
     *
     * @param requestedClaims The new HashMap with the requested claims.
     */
    public void setRequestedClaims(HashMap<String, String> requestedClaims) {

        this.requestedClaims = requestedClaims;
    }
}
