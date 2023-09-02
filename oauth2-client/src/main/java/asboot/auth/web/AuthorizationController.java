/*
 * Copyright 2020-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package asboot.auth.web;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.clientRegistrationId;
import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import jakarta.servlet.http.HttpServletRequest;

/**
 * @author Joe Grandja
 * @since 0.0.1
 */
@Controller
public class AuthorizationController {

	private static final Logger LOG = LoggerFactory.getLogger(AuthorizationController.class);

	@Autowired
	private WebClient webClient;
	@Value("${messages.base-uri}")
	private String messagesBaseUri;
	@Value("${uaa.token-introspect-uri}")
	private String uaaTokenIntrospectUri;
	@Value("${uaa.token-revoke-uri}")
	private String uaaTokenRevokeUri;

	@GetMapping(value = "/token/introspect")
	public String tokenIntrospect(Model model,
			@RegisteredOAuth2AuthorizedClient("messaging-client-oidc") OAuth2AuthorizedClient authorizedClient) {

		OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
		String tokenValue = accessToken.getTokenValue();
		LOG.info("tokenValue:{}", tokenValue);

		ClientRegistration clientRegistration = authorizedClient.getClientRegistration();
		String clientId = clientRegistration.getClientId();
		LOG.info("clientId:{}", clientId);
		String clientSecret = clientRegistration.getClientSecret();
		LOG.info("clientSecret:{}", clientSecret);

		String src = String.format("%s:%s", clientId, clientSecret);
		LOG.info("src:{}", src);

		String authorization = Base64.getEncoder().encodeToString(src.getBytes());
		LOG.info("authorization:{}", authorization);

		// @formatter:off
		String messages = this.webClient
				.post()
				.uri(this.uaaTokenIntrospectUri)
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.header("Authorization", "Basic " + authorization)
				.body(BodyInserters.fromFormData("token", tokenValue))
				.retrieve()
				.bodyToMono(String.class)
				.block();
		// @formatter:on
		model.addAttribute("messages", messages);
		
		
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		LOG.info("authentication:{}", authentication);

		return "index";
	}

	@GetMapping(value = "/token/revoke")
	public String tokenRevoke(Model model,
			@RegisteredOAuth2AuthorizedClient("messaging-client-oidc") OAuth2AuthorizedClient authorizedClient) {

		OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
		String tokenValue = accessToken.getTokenValue();
		LOG.info("tokenValue:{}", tokenValue);

		ClientRegistration clientRegistration = authorizedClient.getClientRegistration();
		String clientId = clientRegistration.getClientId();
		LOG.info("clientId:{}", clientId);
		String clientSecret = clientRegistration.getClientSecret();
		LOG.info("clientSecret:{}", clientSecret);

		String src = String.format("%s:%s", clientId, clientSecret);
		LOG.info("src:{}", src);

		String authorization = Base64.getEncoder().encodeToString(src.getBytes());
		LOG.info("authorization:{}", authorization);

		// @formatter:off
		String messages = this.webClient
				.post()
				.uri(this.uaaTokenRevokeUri)
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.header("Authorization", "Basic " + authorization)
				.body(BodyInserters.fromFormData("token", tokenValue).with("token_type_hint", "access_token"))
				.retrieve()
				.bodyToMono(String.class)
				.block();
		// @formatter:on
		model.addAttribute("messages", messages);

		return "redirect:/index";
	}

	@GetMapping(value = "/authorize", params = "grant_type=authorization_code")
	public String authorizationCodeGrant(Model model,
			@RegisteredOAuth2AuthorizedClient("messaging-client-authorization-code") OAuth2AuthorizedClient authorizedClient) {
		
		OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
		String tokenValue = accessToken.getTokenValue();
		LOG.info("tokenValue:{}", tokenValue);

		// @formatter:off
		String[] messages = this.webClient
				.get()
				.uri(this.messagesBaseUri)
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.retrieve()
				.bodyToMono(String[].class)
				.block();
		// @formatter:on
		model.addAttribute("messages", messages);

		return "index";
	}

	// '/authorized' is the registered 'redirect_uri' for authorization_code
	@GetMapping(value = "/authorized", params = OAuth2ParameterNames.ERROR)
	public String authorizationFailed(Model model, HttpServletRequest request) {
		String errorCode = request.getParameter(OAuth2ParameterNames.ERROR);
		if (StringUtils.hasText(errorCode)) {
			model.addAttribute("error",
					new OAuth2Error(errorCode, request.getParameter(OAuth2ParameterNames.ERROR_DESCRIPTION),
							request.getParameter(OAuth2ParameterNames.ERROR_URI)));
		}

		return "index";
	}

	@GetMapping(value = "/authorize", params = "grant_type=client_credentials")
	public String clientCredentialsGrant(Model model) {

		// @formatter:off
		String[] messages = this.webClient
				.get()
				.uri(this.messagesBaseUri)
				.attributes(clientRegistrationId("messaging-client-client-credentials"))
				.retrieve()
				.bodyToMono(String[].class)
				.block();
		// @formatter:on
		model.addAttribute("messages", messages);

		return "index";
	}
}
