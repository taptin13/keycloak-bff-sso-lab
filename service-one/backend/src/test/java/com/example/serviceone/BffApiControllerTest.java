package com.example.serviceone;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

class BffApiControllerTest {
    @Test
    void startsOidcLoginThroughItsOwnBff() {
        BffApiController controller = controller(RestClient.builder());

        assertThat(controller.login()).isEqualTo("redirect:/oauth2/authorization/keycloak");
    }

    @Test
    void usesItsOwnServerSessionForTheAllowlistedApi() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo("http://kong:8000/service-one/api/hello"))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header("Authorization", "Bearer server-side-token"))
                .andRespond(withSuccess(
                        "{\"service\":\"service-one\",\"username\":\"testuser\"}",
                        MediaType.APPLICATION_JSON));
        BffApiController controller = controller(builder);
        MockHttpServletRequest request = authenticatedRequest("server-side-token", "refresh-token",
                Instant.now().plusSeconds(120));

        var response = controller.hello(request);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(new String(response.getBody())).contains("\"service\":\"service-one\"");
        server.verify();
    }

    @Test
    void rejectsApiRequestsWithoutItsOwnSession() {
        org.assertj.core.api.Assertions.assertThatThrownBy(
                () -> controller(RestClient.builder()).hello(new MockHttpServletRequest()))
                .isInstanceOf(org.springframework.web.server.ResponseStatusException.class)
                .hasMessageContaining("No authenticated user session");
    }

    @Test
    void refreshesExpiredTokenAndStoresTheRotatedRefreshToken() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo("http://keycloak/token"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("Authorization", "Basic ZGVtby1jbGllbnQ6ZGVtby1zZWNyZXQ="))
                .andExpect(content().string("grant_type=refresh_token&refresh_token=refresh-token"))
                .andRespond(withSuccess("""
                        {"access_token":"refreshed-access","refresh_token":"rotated-refresh","expires_in":300}
                        """, MediaType.APPLICATION_JSON));
        server.expect(requestTo("http://kong:8000/service-one/api/hello"))
                .andExpect(header("Authorization", "Bearer refreshed-access"))
                .andRespond(withSuccess("{\"service\":\"service-one\"}", MediaType.APPLICATION_JSON));
        MockHttpServletRequest request = authenticatedRequest("expired-access", "refresh-token",
                Instant.parse("2000-01-01T00:00:00Z"));

        controller(builder).hello(request);

        assertThat(request.getSession(false).getAttribute("BFF_ACCESS_TOKEN")).isEqualTo("refreshed-access");
        assertThat(request.getSession(false).getAttribute("BFF_REFRESH_TOKEN")).isEqualTo("rotated-refresh");
        server.verify();
    }

    @Test
    void invalidatesSessionWhenKeycloakRejectsRefreshToken() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo("http://keycloak/token"))
                .andRespond(org.springframework.test.web.client.response.MockRestResponseCreators
                        .withStatus(HttpStatus.BAD_REQUEST)
                        .contentType(MediaType.APPLICATION_JSON)
                        .body("{\"error\":\"invalid_grant\"}"));
        MockHttpServletRequest request = authenticatedRequest("expired-access", "revoked-refresh",
                Instant.parse("2000-01-01T00:00:00Z"));

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> controller(builder).hello(request))
                .isInstanceOf(org.springframework.web.server.ResponseStatusException.class)
                .hasMessageContaining("Session token refresh was rejected");
        assertThat(request.getSession(false)).isNull();
        server.verify();
    }

    private BffApiController controller(RestClient.Builder builder) {
        return new BffApiController(
                builder,
                "http://kong:8000",
                "http://keycloak/token",
                "demo-client",
                "demo-secret",
                "SERVICE_ONE_SESSION",
                false);
    }

    private MockHttpServletRequest authenticatedRequest(String accessToken, String refreshToken, Instant expiresAt) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        var session = request.getSession(true);
        session.setAttribute("BFF_ACCESS_TOKEN", accessToken);
        session.setAttribute("BFF_REFRESH_TOKEN", refreshToken);
        session.setAttribute("BFF_TOKEN_EXPIRES_AT", expiresAt);
        session.setAttribute("BFF_USERNAME", "testuser");
        return request;
    }
}
