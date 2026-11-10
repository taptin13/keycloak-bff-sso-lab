package com.example.servicetwo;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;

@Configuration
public class SecurityConfig {
    @Bean
    ClientRegistrationRepository clientRegistrationRepository(
            @Value("${app.oidc.issuer-uri}") String issuerUri,
            @Value("${app.oidc.authorization-uri}") String authorizationUri,
            @Value("${app.oidc.token-uri}") String tokenUri,
            @Value("${app.oidc.jwk-set-uri}") String jwkSetUri,
            @Value("${app.oidc.user-info-uri}") String userInfoUri,
            @Value("${app.oidc.redirect-uri}") String redirectUri,
            @Value("${app.oidc.client-id}") String clientId,
            @Value("${app.oidc.client-secret}") String clientSecret) {
        ClientRegistration registration = ClientRegistration.withRegistrationId("keycloak")
                .clientId(clientId)
                .clientSecret(clientSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(redirectUri)
                .scope("openid", "profile", "email")
                .authorizationUri(authorizationUri)
                .tokenUri(tokenUri)
                .jwkSetUri(jwkSetUri)
                .userInfoUri(userInfoUri)
                .userNameAttributeName("preferred_username")
                .clientName("Keycloak")
                .issuerUri(issuerUri)
                .build();
        return new InMemoryClientRegistrationRepository(registration);
    }

    @Bean
    JwtDecoderFactory<ClientRegistration> idTokenDecoderFactory(
            @Value("${app.oidc.issuer-uri}") String issuerUri) {
        OidcIdTokenDecoderFactory factory = new OidcIdTokenDecoderFactory();
        factory.setJwtValidatorFactory(registration -> JwtValidators.createDefaultWithIssuer(issuerUri));
        return factory;
    }

    @Bean
    JwtDecoder jwtDecoder(
            @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuerUri,
            @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}") String jwkSetUri,
            @Value("${app.api.audience}") String audience) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
        decoder.setJwtValidator(new org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(issuerUri), audienceValidator(audience)));
        return decoder;
    }

    static OAuth2TokenValidator<Jwt> audienceValidator(String audience) {
        return jwt -> jwt.getAudience().contains(audience)
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(
                        new OAuth2Error("invalid_token", "Required audience is missing", null));
    }

    @Bean
    OAuth2AuthorizationRequestResolver authorizationRequestResolver(
            ClientRegistrationRepository registrations) {
        DefaultOAuth2AuthorizationRequestResolver resolver = new DefaultOAuth2AuthorizationRequestResolver(
                registrations, OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
        resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
        return resolver;
    }

    @Bean
    SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            OAuth2AuthorizedClientRepository authorizedClientRepository,
            OAuth2AuthorizationRequestResolver authorizationRequestResolver,
            @Value("${server.servlet.session.cookie.secure:true}") boolean secureCookie,
            @Value("${app.frontend-url}") String frontendUrl) throws Exception {
        CookieCsrfTokenRepository csrfRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        csrfRepository.setCookieName("SERVICE-TWO-XSRF-TOKEN");
        csrfRepository.setCookieCustomizer(cookie -> cookie.path("/").secure(secureCookie).sameSite("Strict"));
        CsrfTokenRequestAttributeHandler csrfHandler = new CsrfTokenRequestAttributeHandler();
        csrfHandler.setCsrfRequestAttributeName("_csrf");

        return http
                .csrf(csrf -> csrf
                        .csrfTokenRepository(csrfRepository)
                        .csrfTokenRequestHandler(csrfHandler))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/actuator/health", "/auth/login", "/oauth2/**", "/login/oauth2/**")
                        .permitAll()
                        .requestMatchers("/bff/**", "/csrf").permitAll()
                        .anyRequest().authenticated())
                .oauth2Login(login -> login
                        .authorizationEndpoint(endpoint ->
                                endpoint.authorizationRequestResolver(authorizationRequestResolver))
                        .successHandler((request, response, authentication) -> {
                            var client = authorizedClientRepository.loadAuthorizedClient(
                                    "keycloak", authentication, request);
                            if (client == null || client.getAccessToken() == null) {
                                throw new IllegalStateException("Keycloak login did not provide an access token");
                            }
                            var session = request.getSession(true);
                            session.setAttribute("BFF_ACCESS_TOKEN", client.getAccessToken().getTokenValue());
                            session.setAttribute("BFF_REFRESH_TOKEN", client.getRefreshToken() == null
                                    ? null
                                    : client.getRefreshToken().getTokenValue());
                            session.setAttribute("BFF_TOKEN_EXPIRES_AT", client.getAccessToken().getExpiresAt());
                            String username = authentication.getPrincipal()
                                    instanceof org.springframework.security.oauth2.core.oidc.user.OidcUser oidcUser
                                            ? oidcUser.getPreferredUsername()
                                            : authentication.getName();
                            session.setAttribute("BFF_USERNAME", username);
                            authorizedClientRepository.removeAuthorizedClient(
                                    "keycloak", authentication, request, response);
                            response.setHeader("Cache-Control", "no-store");
                            response.setHeader("Referrer-Policy", "no-referrer");
                            response.sendRedirect(frontendUrl);
                        }))
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()))
                .build();
    }
}
