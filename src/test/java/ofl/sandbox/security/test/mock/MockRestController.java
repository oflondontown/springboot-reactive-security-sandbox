package ofl.sandbox.security.test.mock;

import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Profile({"security-test","security-disabled-test"})
public class MockRestController {

}
