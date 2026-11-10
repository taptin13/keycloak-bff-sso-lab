package com.example.servicetwo;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.server.ResponseStatusException;

import static org.springframework.http.HttpStatus.BAD_GATEWAY;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Controller
public class BffApiController {
    private static final String ACCESS_TOKEN = "BFF_ACCESS_TOKEN";
    private static final String REFRESH_TOKEN = "BFF_REFRESH_TOKEN";
    private static final String TOKEN_EXPIRES_AT = "BFF_TOKEN_EXPIRES_AT";
    private static final String USERNAME = "BFF_USERNAME";

    private final RestClient restClient;
    private final String kongUrl;
    private final String tokenUri;
    private final String clientId;
    private final String clientSecret;
    private final String sessionCookieName;
    private final boolean secureSessionCookie;

    BffApiController(
            RestClient.Builder restClientBuilder,
            @Value("${app.kong.url}") String kongUrl,
            @Value("${app.oidc.token-uri}") String tokenUri,
            @Value("${app.oidc.client-id}") String clientId,
            @Value("${app.oidc.client-secret}") String clientSecret,
            @Value("${server.servlet.session.cookie.name}") String sessionCookieName,
            @Value("${server.servlet.session.cookie.secure:true}") boolean secureSessionCookie) {
        this.restClient = restClientBuilder.build();
        this.kongUrl = kongUrl;
        this.tokenUri = tokenUri;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.sessionCookieName = sessionCookieName;
        this.secureSessionCookie = secureSessionCookie;
    }

    @GetMapping("/auth/login")
    String login() {
        return "redirect:/oauth2/authorization/keycloak";
    }

    @GetMapping("/bff/auth/user")
    @ResponseBody
    Map<String, String> user(HttpServletRequest request) {
        HttpSession session = authenticatedSession(request);
        return Map.of("username", (String) session.getAttribute(USERNAME));
    }

    @PostMapping("/bff/auth/logout")
    ResponseEntity<Void> logout(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        ResponseCookie expiredCookie = ResponseCookie.from(sessionCookieName, "")
                .httpOnly(true)
                .secure(secureSessionCookie)
                .sameSite("Lax")
                .path("/")
                .maxAge(0)
                .build();
        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, expiredCookie.toString())
                .cacheControl(CacheControl.noStore())
                .build();
    }

    @GetMapping("/bff/api/hello")
    ResponseEntity<byte[]> hello(HttpServletRequest request) {
        HttpSession session = authenticatedSession(request);
        String accessToken = getCurrentAccessToken(session);
        try {
            return restClient.get()
                    .uri(kongUrl + "/service-two/api/hello")
                    .headers(headers -> headers.setBearerAuth(accessToken))
                    .exchange((upstreamRequest, upstreamResponse) -> {
                        HttpHeaders headers = new HttpHeaders();
                        if (upstreamResponse.getHeaders().getContentType() != null) {
                            headers.setContentType(upstreamResponse.getHeaders().getContentType());
                        }
                        return new ResponseEntity<>(
                                upstreamResponse.getBody().readAllBytes(),
                                headers,
                                upstreamResponse.getStatusCode());
                    });
        } catch (ResourceAccessException exception) {
            throw new ResponseStatusException(BAD_GATEWAY, "Could not reach the API gateway", exception);
        }
    }

    private HttpSession authenticatedSession(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null || !(session.getAttribute(ACCESS_TOKEN) instanceof String)) {
            throw new ResponseStatusException(UNAUTHORIZED, "No authenticated user session");
        }
        return session;
    }

    private String getCurrentAccessToken(HttpSession session) {
        synchronized (session) {
            Instant expiresAt = (Instant) session.getAttribute(TOKEN_EXPIRES_AT);
            String accessToken = (String) session.getAttribute(ACCESS_TOKEN);
            if (accessToken != null && expiresAt != null
                    && expiresAt.isAfter(Instant.now().plusSeconds(30))) {
                return accessToken;
            }
            String refreshToken = (String) session.getAttribute(REFRESH_TOKEN);
            if (refreshToken == null || refreshToken.isBlank()) {
                session.invalidate();
                throw new ResponseStatusException(UNAUTHORIZED, "Session token has expired");
            }
            LinkedMultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add("grant_type", "refresh_token");
            form.add("refresh_token", refreshToken);
            try {
                RefreshedToken refreshed = restClient.post()
                        .uri(tokenUri)
                        .headers(headers -> headers.setBasicAuth(
                                URLEncoder.encode(clientId, StandardCharsets.UTF_8),
                                URLEncoder.encode(clientSecret, StandardCharsets.UTF_8)))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .body(form)
                        .retrieve()
                        .body(RefreshedToken.class);
                if (refreshed == null || refreshed.accessToken() == null
                        || refreshed.accessToken().isBlank() || refreshed.expiresIn() <= 0) {
                    session.invalidate();
                    throw new ResponseStatusException(UNAUTHORIZED, "Could not refresh the session token");
                }
                session.setAttribute(ACCESS_TOKEN, refreshed.accessToken());
                if (refreshed.refreshToken() != null && !refreshed.refreshToken().isBlank()) {
                    session.setAttribute(REFRESH_TOKEN, refreshed.refreshToken());
                }
                session.setAttribute(TOKEN_EXPIRES_AT, Instant.now().plusSeconds(refreshed.expiresIn()));
                return refreshed.accessToken();
            } catch (HttpClientErrorException exception) {
                session.invalidate();
                throw new ResponseStatusException(UNAUTHORIZED, "Session token refresh was rejected");
            } catch (ResourceAccessException exception) {
                throw new ResponseStatusException(BAD_GATEWAY, "Could not reach the identity provider", exception);
            }
        }
    }

    private record RefreshedToken(
            @com.fasterxml.jackson.annotation.JsonProperty("access_token") String accessToken,
            @com.fasterxml.jackson.annotation.JsonProperty("refresh_token") String refreshToken,
            @com.fasterxml.jackson.annotation.JsonProperty("expires_in") long expiresIn) {
    }
}
