package com.fooddelivery.common.security;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class IdentityTokenServiceTest {

    private final IdentityTokenService identityTokenService = new IdentityTokenService("my-super-secret-key-that-is-long-enough-to-be-secure", new org.springframework.mock.env.MockEnvironment());

    @Test
    void shouldGenerateAndVerifyValidSignature() {
        String userId = "user-123";
        String roles = "ROLE_USER";
        String phone = "1234567890";
        String sessionId = "session-1";
        long issuedAt = 1692698400000L;

        String signature = identityTokenService.sign(userId, roles, phone, sessionId, issuedAt);
        assertNotNull(signature);
        
        boolean isValid = identityTokenService.verify(signature, userId, roles, phone, sessionId, issuedAt);
        assertTrue(isValid);
    }

    @Test
    void shouldRejectTamperedSignature() {
        String userId = "user-123";
        String roles = "ROLE_USER";
        String phone = "1234567890";
        String sessionId = "session-1";
        long issuedAt = 1692698400000L;

        String signature = identityTokenService.sign(userId, roles, phone, sessionId, issuedAt);
        assertNotNull(signature);
        
        boolean isValid = identityTokenService.verify(signature, userId, "ROLE_ADMIN", phone, sessionId, issuedAt);
        assertFalse(isValid);
    }

    // ---- Cross-implementation drift pin -------------------------------------------------------
    // ApiGateway.GlobalJwtAuthFilter re-implements this signing because it cannot depend on
    // common-library (spring-boot-starter-web breaks Spring Cloud Gateway). Both sides assert the
    // SAME known-answer vector, computed independently, so changing the payload format, separator,
    // algorithm, Base64 variant or padding on either side fails that side's build.
    // If you change this vector, you must change it in BOTH modules.
    static final String PIN_KEY   = "pinned-known-answer-vector-do-not-change";
    static final String PIN_USER  = "11111111-1111-1111-1111-111111111111";
    static final String PIN_ROLES = "ROLE_CUSTOMER,ROLE_ADMIN";
    static final String PIN_PHONE = "+919999999999";
    static final String PIN_SESS  = "22222222-2222-2222-2222-222222222222";
    static final long   PIN_IAT   = 1700000000000L;
    static final String PIN_SIG   = "qMbQt6aFqfO2Nrd75y9v6hSLNh7E0LRfSYTNMorrY0E";

    @Test
    void matchesTheCrossImplementationVector() {
        var svc = new IdentityTokenService(PIN_KEY, new org.springframework.mock.env.MockEnvironment());
        assertEquals(PIN_SIG, svc.sign(PIN_USER, PIN_ROLES, PIN_PHONE, PIN_SESS, PIN_IAT),
                "Identity signing changed. ApiGateway.GlobalJwtAuthFilter.signIdentity must change "
                + "identically or every authenticated request 403s.");
    }

    @Test
    void prodRefusesABlankSecret() {
        var env = new org.springframework.mock.env.MockEnvironment();
        env.setActiveProfiles("prod");
        assertThrows(IllegalStateException.class, () -> new IdentityTokenService("", env));
    }

    @Test
    void prodRefusesTheDevSecret() {
        var env = new org.springframework.mock.env.MockEnvironment();
        env.setActiveProfiles("prod");
        assertThrows(IllegalStateException.class,
                () -> new IdentityTokenService(IdentityTokenService.DEV_SECRET, env));
    }

    @Test
    void prodAcceptsARealSecret() {
        var env = new org.springframework.mock.env.MockEnvironment();
        env.setActiveProfiles("prod");
        assertDoesNotThrow(() -> new IdentityTokenService(PIN_KEY, env));
    }
}
