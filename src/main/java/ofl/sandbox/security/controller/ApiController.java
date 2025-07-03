package ofl.sandbox.security.controller;
        import lombok.extern.slf4j.Slf4j;
        import org.springframework.context.annotation.Profile;
        import org.springframework.security.access.prepost.PreAuthorize;
        import org.springframework.web.bind.annotation.*;
        import reactor.core.publisher.Mono;

@Slf4j
@RestController
@RequestMapping("/api/request")
@Profile("webservice")
public class ApiController {

    @GetMapping("/hello")
    @PreAuthorize("hasAuthority('CAN_VIEW')")
    public Mono<String> hello() {
        log.info("Hello authenticated user!");
        return Mono.just("Hello authenticated user!");
    }

    @GetMapping("/trade")
    @PreAuthorize("hasAuthority('CAN_TRADE')")
    public Mono<String> trade() {
        log.info("Hello authenticated trader!");
        return Mono.just("Hello trader!");
    }
}
