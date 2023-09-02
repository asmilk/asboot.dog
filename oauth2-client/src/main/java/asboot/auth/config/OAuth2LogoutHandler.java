package asboot.auth.config;

import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class OAuth2LogoutHandler implements LogoutHandler {

	private static final Logger LOG = LoggerFactory.getLogger(OAuth2LogoutHandler.class);

	@Value("${uaa.token-revoke-uri}")
	private String uaaTokenRevokeUri;

	@Autowired
	private WebClient webClient;

	@Autowired
	private ClientRegistrationRepository clientRegistrationRepository;

	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

		if (authentication instanceof OAuth2AuthenticationToken) {
			OAuth2AuthenticationToken oAuth2AuthenticationToken = (OAuth2AuthenticationToken) authentication;
			OAuth2User oAuth2User = oAuth2AuthenticationToken.getPrincipal();
			if (oAuth2User instanceof DefaultOidcUser) {
				DefaultOidcUser defaultOidcUser = (DefaultOidcUser) oAuth2User;
				String tokenValue = defaultOidcUser.getIdToken().getTokenValue();
				LOG.info("tokenValue:{}", tokenValue);

				ClientRegistration clientRegistration = this.clientRegistrationRepository
						.findByRegistrationId(oAuth2AuthenticationToken.getAuthorizedClientRegistrationId());
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
				LOG.info("messages:{}", messages);
			}

		}

	}

}
