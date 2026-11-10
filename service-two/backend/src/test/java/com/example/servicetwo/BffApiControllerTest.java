package com.example.servicetwo;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

class BffApiControllerTest {
    @Test
    void startsOidcLoginThroughItsOwnBff() {
        assertThat(controller(RestClient.builder()).login())
                .isEqualTo("redirect:/oauth2/authorization/keycloak");
    }

    @Test
    void usesItsOwnServerSessionForTheAllowlistedApi() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo("http://kong:8000/service-two/api/hello"))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header("Authorization", "Bearer server-side-token"))
                .andRespond(withSuccess(
                        "{\"service\":\"service-two\",\"username\":\"testuser\"}",
                        MediaType.APPLICATION_JSON));
        MockHttpServletRequest request = new MockHttpServletRequest();
        var session = request.getSession(true);
        session.setAttribute("BFF_ACCESS_TOKEN", "server-side-token");
        session.setAttribute("BFF_REFRESH_TOKEN", "refresh-token");
        session.setAttribute("BFF_TOKEN_EXPIRES_AT", Instant.now().plusSeconds(120));
        session.setAttribute("BFF_USERNAME", "testuser");

        var response = controller(builder).hello(request);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(new String(response.getBody())).contains("\"service\":\"service-two\"");
        server.verify();
    }

    @Test
    void rejectsApiRequestsWithoutItsOwnSession() {
        org.assertj.core.api.Assertions.assertThatThrownBy(
                () -> controller(RestClient.builder()).hello(new MockHttpServletRequest()))
                .isInstanceOf(org.springframework.web.server.ResponseStatusException.class)
                .hasMessageContaining("No authenticated user session");
    }

    private BffApiController controller(RestClient.Builder builder) {
        return new BffApiController(
                builder,
                "http://kong:8000",
                "http://keycloak/token",
                "demo-client",
                "demo-secret",
                "SERVICE_TWO_SESSION",
                false);
    }
}
