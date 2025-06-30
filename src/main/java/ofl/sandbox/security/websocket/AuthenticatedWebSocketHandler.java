package ofl.sandbox.security.websocket;

import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;
import ofl.sandbox.security.jwt.JwtService;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.socket.*;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.List;
import java.util.Optional;

@Slf4j
@Component
public class AuthenticatedWebSocketHandler implements WebSocketHandler {

    private final JwtService jwtService;

    public AuthenticatedWebSocketHandler(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    public Mono<Void> handle(WebSocketSession session) {
        URI uri = session.getHandshakeInfo().getUri();
        Optional<String> tokenOpt = getTokenFromUri(uri);

        if (tokenOpt.isEmpty()) {
            log.error("Token is empty");
            return handleInvalidConnection(session, CloseStatus.BAD_DATA, "Token is empty");
        }

        try {
            List<String> entitlements = jwtService.getEntitlements(tokenOpt.get());

            if(!entitlements.contains("CAN_CONNECT_WS")) {
                log.error("Not entitled for WS");
                return handleInvalidConnection(session, CloseStatus.NOT_ACCEPTABLE, "Missing entitlement: CAN_CONNECT_WS");
            }

        } catch(JwtException e) {
            log.error("Bad token", e);
            return session.close(CloseStatus.BAD_DATA);
        }

        String username = jwtService.getUsername(tokenOpt.get());
        log.info("Sending to {}", username);
        return session.send(session.receive()
                .map(msg -> session.textMessage("Echo from " + username + ": " + msg.getPayloadAsText())));
    }

    private Mono<Void> handleInvalidConnection(WebSocketSession session, CloseStatus closeStatus, String invalidReason) {
        return session.send(Mono.just(
                session.textMessage(invalidReason)
        )).then(session.close(closeStatus.withReason(invalidReason)));
    }

    private Optional<String> getTokenFromUri(URI uri) {
        List<String> queryParts = List.of(uri.getQuery().split("&"));
        return queryParts.stream()
                .filter(q -> q.startsWith("token="))
                .map(q -> q.substring(6))
                .findFirst();
    }
}
