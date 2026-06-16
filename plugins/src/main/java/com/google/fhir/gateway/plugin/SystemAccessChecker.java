/*
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.fhir.gateway.plugin;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.rest.api.RequestTypeEnum;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.common.base.Preconditions;
import com.google.fhir.gateway.HttpFhirClient;
import com.google.fhir.gateway.JwtUtil;
import com.google.fhir.gateway.interfaces.AccessChecker;
import com.google.fhir.gateway.interfaces.AccessCheckerFactory;
import com.google.fhir.gateway.interfaces.AccessDecision;
import com.google.fhir.gateway.interfaces.NoOpAccessDecision;
import com.google.fhir.gateway.interfaces.PatientFinder;
import com.google.fhir.gateway.interfaces.RequestDetailsReader;
import com.google.fhir.gateway.plugin.SmartFhirScope.Permission;
import com.google.fhir.gateway.plugin.SmartFhirScope.Principal;
import java.util.Arrays;
import javax.inject.Named;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This access-checker uses the `scope` claims in the access token to decide whether access to a
 * request should be granted or not. The `scope` claims are expected to be SMART-on-FHIR compliant
 * with system/* scopes.
 *
 * <p>This is designed for Backend Services (server-to-server) authentication where there is no
 * patient context. It supports full CRUDS (Create, Read, Update, Delete, Search) operations on FHIR
 * resources based on system/* scopes.
 *
 * <p>Example scopes: - system/Patient.read : Read Patient resources - system/Observation.cruds:
 * Full CRUDS on Observation resources - system/*.cruds : Full CRUDS on all resource types
 */
public class SystemAccessChecker implements AccessChecker {
  private static final Logger logger = LoggerFactory.getLogger(SystemAccessChecker.class);

  private final FhirContext fhirContext;
  private final SmartScopeChecker smartScopeChecker;

  private SystemAccessChecker(FhirContext fhirContext, SmartScopeChecker smartScopeChecker) {
    Preconditions.checkNotNull(smartScopeChecker);
    Preconditions.checkNotNull(fhirContext);
    this.fhirContext = fhirContext;
    this.smartScopeChecker = smartScopeChecker;
  }

  @Override
  public AccessDecision checkAccess(RequestDetailsReader requestDetails) {
    String resourceType = requestDetails.getResourceName();

    // Handle Bundle requests separately
    if (requestDetails.getRequestType() == RequestTypeEnum.POST && resourceType == null) {
      // For Bundle, we need to check permissions for all resources in the bundle
      // For now, require system/*.* or system/Bundle.* permissions
      if (smartScopeChecker.hasPermission("Bundle", Permission.CREATE)
          || smartScopeChecker.hasPermission("*", Permission.CREATE)) {
        logger.info("Access granted for Bundle POST");
        return new NoOpAccessDecision(true);
      }
      logger.warn("Access denied for Bundle POST - missing system/Bundle.c or system/*.c scope");
      return NoOpAccessDecision.accessDenied();
    }

    // Determine required permission based on request type
    Permission requiredPermission = getRequiredPermission(requestDetails.getRequestType());
    if (requiredPermission == null) {
      logger.warn("Unsupported request type: {}", requestDetails.getRequestType());
      return NoOpAccessDecision.accessDenied();
    }

    // Check if the scope has the required permission for this resource type
    boolean hasPermission = smartScopeChecker.hasPermission(resourceType, requiredPermission);

    if (hasPermission) {
      logger.info(
          "Access granted for {} {} with scope system/{}.{}",
          requestDetails.getRequestType(),
          resourceType,
          resourceType,
          requiredPermission);
      return new NoOpAccessDecision(true);
    }

    logger.warn(
        "Access denied for {} {} - missing required scope system/{}.{}",
        requestDetails.getRequestType(),
        resourceType,
        resourceType,
        requiredPermission);
    return NoOpAccessDecision.accessDenied();
  }

  private Permission getRequiredPermission(RequestTypeEnum requestType) {
    switch (requestType) {
      case GET:
        // GET can be either READ or SEARCH depending on whether it's a single resource or query
        // For simplicity, we check READ permission (SEARCH is typically included)
        return Permission.READ;
      case POST:
        return Permission.CREATE;
      case PUT:
      case PATCH:
        return Permission.UPDATE;
      case DELETE:
        return Permission.DELETE;
      default:
        return null;
    }
  }

  @Named("system")
  public static class Factory implements AccessCheckerFactory {
    private static final String SCOPES_CLAIM = "scope";

    private SmartScopeChecker getSmartFhirPermissionChecker(DecodedJWT jwt) {
      String scopesClaim = JwtUtil.getClaimOrDie(jwt, SCOPES_CLAIM);
      String[] scopes = scopesClaim.strip().split("\\s+");
      return new SmartScopeChecker(
          SmartFhirScope.extractSmartFhirScopesFromTokens(Arrays.asList(scopes)), Principal.SYSTEM);
    }

    @Override
    public AccessChecker create(
        DecodedJWT jwt,
        HttpFhirClient httpFhirClient,
        FhirContext fhirContext,
        PatientFinder patientFinder) {

      SmartScopeChecker smartScopeChecker = getSmartFhirPermissionChecker(jwt);
      logger.info("Creating SystemAccessChecker with system/* scopes");

      return new SystemAccessChecker(fhirContext, smartScopeChecker);
    }
  }
}
