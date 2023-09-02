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
package asboot.auth.config;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

/**
 * @author Joe Grandja
 * @since 0.0.1
 */
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class SecurityConfig {
	
	@Value("${uaa.logout-uri}")
	private String uaaLogoutUri;

	@Autowired
	private OAuth2LogoutHandler oAuth2LogoutHandler;
	
	@Autowired
	private ClientRegistrationRepository clientRegistrationRepository;

	@Bean
	WebSecurityCustomizer webSecurityCustomizer() {
		return (web) -> web.ignoring().requestMatchers("/webjars/**", "/favicon.ico");
	}

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		
		// @formatter:off
		http
			.authorizeHttpRequests(authorize -> authorize
				.requestMatchers("/index").permitAll()
				.anyRequest().authenticated())
			.logout(logout -> logout
//				.addLogoutHandler(this.oAuth2LogoutHandler)
				.clearAuthentication(true)
				.invalidateHttpSession(true)
//				.logoutSuccessUrl(this.uaaLogoutUri)
				.logoutSuccessHandler(oidcLogoutSuccessHandler())
				)
			
			.oauth2Login(oauth2Login -> oauth2Login
				.loginPage("/oauth2/authorization/messaging-client-oidc"))
			.oauth2Client(withDefaults());
		// @formatter:on
		return http.build();
	}
	
	private LogoutSuccessHandler oidcLogoutSuccessHandler() {
		OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler =
				new OidcClientInitiatedLogoutSuccessHandler(this.clientRegistrationRepository);

		// Set the location that the End-User's User Agent will be redirected to
		// after the logout has been performed at the Provider
		oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}/index");

		return oidcLogoutSuccessHandler;
	}

}
