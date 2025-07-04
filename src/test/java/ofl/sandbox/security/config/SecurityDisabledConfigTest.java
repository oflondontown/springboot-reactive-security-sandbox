package ofl.sandbox.security.config;

import ofl.sandbox.security.controller.ApiController;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.reactive.server.WebTestClient;

@WebFluxTest
@ContextConfiguration(classes = {ApiController.class})
@Import({NoSecurityConfig.class, WebClientConfig.class})
@ActiveProfiles("webservice")
public class SecurityDisabledConfigTest {

    @Autowired
    WebTestClient webTestClient;

    @Test
    public void test() {
        webTestClient
                .get()
                .uri("/api/request/test")
                .exchange()
                .expectStatus().isOk();
    }
}
