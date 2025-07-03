package ofl.sandbox.security.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
@Profile({"auth", "webservice"})
@Slf4j
public class UserEntitlementsService {

    private final Map<String, List<String>> entitlementCache = Map.of(
            "alice", List.of("CAN_TRADE", "CAN_VIEW", "CAN_SEE_DATA"),
            "bob", List.of("CAN_VIEW"),
            "chris", List.of("CAN_CONNECT_WS")
    );


    public UserEntitlementsService() {
    }

    public List<String> getEntitlements(String userId) {
        if(!entitlementCache.containsKey(userId)) {
            log.error("Unauthorised login for {}", userId);
            return null;
        }

        return entitlementCache.get(userId);
    }
}
