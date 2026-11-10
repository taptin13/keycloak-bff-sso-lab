package com.example.servicetwo;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.jwt.Jwt;

class SecurityConfigTest {
    @Test
    void createsServiceTwoConfidentialClientWithStateAndPkce() {
        SecurityConfig config = new SecurityConfig();
        ClientRegistrationRepository registrations = config.clientRegistrationRepository(
                "http://localhost:8080/realms/demo",
                "http://localhost:8080/realms/demo/protocol/openid-connect/auth",
                "http://keycloak:8080/realms/demo/protocol/openid-connect/token",
                "http://keycloak:8080/realms/demo/protocol/openid-connect/certs",
                "http://keycloak:8080/realms/demo/protocol/openid-connect/userinfo",
                "http://localhost:5174/login/oauth2/code/keycloak",
                "demo-service-two",
                "demo-service-two-secret");
        var resolver = config.authorizationRequestResolver(registrations);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oauth2/authorization/keycloak");
        request.setServletPath("/oauth2/authorization/keycloak");

        var authorizationRequest = resolver.resolve(request);

        assertThat(authorizationRequest.getState()).isNotBlank();
        assertThat(authorizationRequest.getClientId()).isEqualTo("demo-service-two");
        assertThat(authorizationRequest.getRedirectUri())
                .isEqualTo("http://localhost:5174/login/oauth2/code/keycloak");
        assertThat(authorizationRequest.getAdditionalParameters())
                .containsEntry("code_challenge_method", "S256")
                .containsKey("code_challenge");
        assertThat(authorizationRequest.getAttributes()).containsKey("code_verifier");
    }

    @Test
    void acceptsOnlyServiceTwoAudience() {
        Jwt serviceTwoJwt = Jwt.withTokenValue("token")
                .header("alg", "none")
                .claim("aud", java.util.List.of("service-two-api"))
                .build();
        Jwt serviceOneJwt = Jwt.withTokenValue("token")
                .header("alg", "none")
                .claim("aud", java.util.List.of("service-one-api"))
                .build();

        assertThat(SecurityConfig.audienceValidator("service-two-api").validate(serviceTwoJwt).hasErrors()).isFalse();
        assertThat(SecurityConfig.audienceValidator("service-two-api").validate(serviceOneJwt).hasErrors()).isTrue();
    }
}
