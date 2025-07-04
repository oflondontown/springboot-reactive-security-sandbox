package ofl.sandbox.security.test.mock;

import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@Profile({"security-test","security-disabled-test"})
public class MockRestController {

    @GetMapping("/test")
    public Mono<String> test() {
        return Mono.just("test");
    }
}
