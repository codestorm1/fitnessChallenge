/**
 * Copyright 2012 StackMob
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

package com.stackmob.example;

import com.fitbit.api.FitbitAPIException;
import com.fitbit.api.client.*;
import com.fitbit.api.client.http.AccessToken;
import com.fitbit.api.client.service.FitbitAPIClientService;
import com.fitbit.api.model.APIResourceCredentials;
import com.fitbit.api.common.model.user.UserInfo;

import com.stackmob.core.customcode.CustomCodeMethod;
import com.stackmob.core.rest.ProcessedAPIRequest;
import com.stackmob.core.rest.ResponseToProcess;
import com.stackmob.sdkapi.SDKServiceProvider;
import com.stackmob.sdkapi.LoggerService;


import java.net.HttpURLConnection;
import java.util.*;


public class CreateFitbitUser implements CustomCodeMethod {


    private static final String fitbitSiteBaseUrl = "http://www.fitbit.com";
    private static final String apiBaseUrl = "api.fitbit.com";
    private static final String fitnessChallengeBaseUrl = "http://localhost:4567";
    private static final String clientConsumerKey = "c472de74290e435caa6b6829ff68b9aa";
    private static final String clientSecret = "312f9d3f9d10418bb43938103a73d5fe";
    private static LoggerService logger;
//    private static final FitbitAPIClientService<FitbitApiClientAgent> apiClientService = new FitbitAPIClientService<FitbitApiClientAgent>(
//            new FitbitApiClientAgent(apiBaseUrl, fitnessChallengeBaseUrl, credentialsCache),
//    clientConsumerKey,
//    clientSecret,
//    credentialsCache,
//    entityCache,
//    subscriptionStore
//    );


    @Override
  public String getMethodName() {
    return "create_fitbit_user";
  }

  @Override
  public List<String> getParams() {
    return Arrays.asList("oauth_token", "oauth_token_secret", "oauth_verifier");
  }

public void getTokenCredentials(LocalUserDetail user, FitbitApiClientAgent client, FitbitAPIClientService service) throws FitbitAPIException {
    // Get cached resource credentials:
    APIResourceCredentials resourceCredentials = service.getResourceCredentialsByUser(user);
    if (resourceCredentials == null) {
        throw new FitbitAPIException("User " + user.getUserId() + " does not have resource credentials. Need to grant authorization first.");
    }

    String tempToken = resourceCredentials.getTempToken();
    String tempTokenSecret = resourceCredentials.getTempTokenSecret();
    if (tempToken == null || tempTokenSecret == null) {
        throw new FitbitAPIException("Resource credentials for resource " + user.getUserId() + " are in an invalid state: temporary token or secret is null.");
    }

    AccessToken accessToken = null;
    // Get and save token credentials:
    try {
        logger.debug("temp: " + tempToken + " secret: " + tempTokenSecret + " verifier: " + resourceCredentials.getTempTokenVerifier());
        //accessToken = client.getOAuthAccessToken(tempToken, tempTokenSecret, resourceCredentials.getTempTokenVerifier());
    }
    catch (Exception e) {
        logger.error("failed to get access token", e);
    }
    resourceCredentials.setAccessToken(accessToken.getToken());
    resourceCredentials.setAccessTokenSecret(accessToken.getTokenSecret());
    resourceCredentials.setResourceId(accessToken.getEncodedUserId());
}



    @Override
  public ResponseToProcess execute(ProcessedAPIRequest request, SDKServiceProvider serviceProvider) {
      logger = serviceProvider.getLoggerService(CreateFitbitUser.class);
      logger.debug("create fitbit user ------------------------------");
      Map<String, Object> map = new HashMap<String, Object>();
      map.put("msg", "Someday i will actually create a fitbit user!");

//      RequestContext context = new RequestContext();
//      populate(context, request, response);
      Map<String,String> params = request.getParams();
      String tempTokenReceived = params.get("oauth_token");
      String tempTokenSecret = params.get("oauth_token_secret");
      String tempTokenVerifier = params.get("oauth_verifier");
      map.put("oauth_token", tempTokenReceived);
      map.put("oauth_token_secret", tempTokenSecret);
      map.put("oauth_verifier", tempTokenVerifier);
      //APIResourceCredentials resourceCredentials = context.getApiClientService().getResourceCredentialsByTempToken(tempTokenReceived);
      // The verifier is required in the request to get token credentials:
      String progress = null;
      FitbitAPIClientService service = null;
        FitbitApiClientAgent agent = null;
      try {

          FitbitApiCredentialsCache credCache = new FitbitApiCredentialsCacheMapImpl();
          LocalUserDetail user = new LocalUserDetail("1234567890");
          APIResourceCredentials cred = new APIResourceCredentials(user.getUserId(), tempTokenReceived, tempTokenSecret);
          credCache.saveResourceCredentials(user, cred);
          //FitbitApiEntityCacheMapImpl entityCache = new FitbitApiEntityCacheMapImpl();
          //FitbitApiSubscriptionStorageInMemoryImpl subscriptionStore = new FitbitApiSubscriptionStorageInMemoryImpl();
          APIResourceCredentials savedCred = credCache.getResourceCredentials(user);
          logger.debug(String.format("request token: %s secret: %s verifier: %s", savedCred.getTempToken(), savedCred.getTempTokenSecret(), savedCred.getTempTokenVerifier()));
          logger.debug(String.format("access token: %s secret: %s", savedCred.getAccessToken(), savedCred.getAccessTokenSecret()));
          agent = new FitbitApiClientAgent(apiBaseUrl, fitnessChallengeBaseUrl, credCache);
          logger.debug("trying get user info");
          agent.getCredentialsCache().saveResourceCredentials(user, cred);
          UserInfo userInfo = agent.getUserInfo(user);
          logger.debug("completed get user info");
          map.put("displayname", userInfo.getDisplayName());
          return new ResponseToProcess(HttpURLConnection.HTTP_OK, map);
//          service = new FitbitAPIClientService(agent, clientConsumerKey, clientSecret,
//                  credCache, entityCache, subscriptionStore);
      }
      catch (FitbitAPIException e) {
          logger.error("fail!", e);
          logger.debug("exception :( ", e);
          map.put("error", e.toString() + "---" + e.getMessage());
          map.put("progress", progress);
          return new ResponseToProcess(HttpURLConnection.HTTP_INTERNAL_ERROR, map);
      }
      catch (Exception e) {
          logger.error("fail!", e);
          logger.debug("exception :( ", e);
          map.put("error", e.toString() + "---" + e.getMessage());
          map.put("progress", progress);
          return new ResponseToProcess(HttpURLConnection.HTTP_INTERNAL_ERROR, map);
      }
//      {
//          this.client = client;
//          client.setOAuthConsumer(consumerKey, consumerSecret);
//          subscriberSecret = consumerSecret;
//          this.credentialsCache = credentialsCache;
//          this.entityCache = entityCache;
//          this.subscriptionStore = subscriptionStore;
//      }

//        try {
//            APIResourceCredentials resourceCredentials = null;
//          logger.debug("getting resource creds by temp token");
//          resourceCredentials = service.getResourceCredentialsByTempToken(tempTokenReceived);
//          logger.debug("temp token ver: " + tempTokenVerifier);
//          resourceCredentials.setTempTokenVerifier(tempTokenVerifier);
//          logger.debug("new user detail");
//          LocalUserDetail userDetail = new LocalUserDetail(resourceCredentials.getLocalUserId());
//          // Get token credentials for user:      // BG from fitbit API?
////      try {
////          this.getTokenCredentials(userDetail, agent, service);
////          logger.debug("Got past get token credentials!!!");
//////      } catch (FitbitAPIException e) {
////      }
////      catch (FitbitAPIException e) {
////          map.put("progress2", "was a fitbit exception");
////          map.put("error", e.getMessage() + e.toString());
////          return new ResponseToProcess(HttpURLConnection.HTTP_INTERNAL_ERROR, map);
////      }
////      catch (Exception e) {
//////          log.error("Unable to finish authorization with Fitbit.", e);
//////          request.setAttribute("errors", Collections.singletonList(e.getMessage()));
////          map.put("it", "was not a fitbit exception");
////          map.put("progress2", "failed to get token credentials");
////          map.put("error", e.getMessage() + e.toString());
////          return new ResponseToProcess(HttpURLConnection.HTTP_INTERNAL_ERROR, map);
////      }
//
//            logger.debug("new user detail");
//            UserInfo userInfo = service.getClient().getUserInfo(new LocalUserDetail(resourceCredentials.getLocalUserId()));
////          request.setAttribute("userInfo", userInfo);
////          request.getRequestDispatcher("/fitbitApiAuthExample.jsp").forward(request, response);
//          map.put("displayname", userInfo.getDisplayName());
//          return new ResponseToProcess(HttpURLConnection.HTTP_OK, map);
////      } catch (FitbitAPIException e) {
//      } catch (Exception e) {
//          logger.debug("exception: ", e);
//          map.put("progress3", progress);
//          map.put("error", e.getMessage());
//          return new ResponseToProcess(HttpURLConnection.HTTP_INTERNAL_ERROR, map);
//      }
//
////              // The verifier is required in the request to get token credentials:
////              resourceCredentials.setTempTokenVerifier(tempTokenVerifier);
////              try {
////                  // Get token credentials for user:
////                  context.getApiClientService().getTokenCredentials(new LocalUserDetail(resourceCredentials.getLocalUserId()));
////              } catch (FitbitAPIException e) {
////                  log.error("Unable to finish authorization with Fitbit.", e);
////                  request.setAttribute("errors", Collections.singletonList(e.getMessage()));
////              }
////          }
////      }
//
//
////      return new ResponseToProcess(HttpURLConnection.HTTP_OK, map);
  }

}
