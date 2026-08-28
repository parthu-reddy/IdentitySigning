package com.fooddelivery.common.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;

@Service
public class IdentityTokenService {

    static final String DEV_SECRET = "dev-only-insecure-identity-hmac-secret-override-in-production-12";

    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(IdentityTokenService.class);

    private final byte[] secretKey;

    public IdentityTokenService(@Value("${security.identity.hmac-secret:}") String secretKeyStr,
                                org.springframework.core.env.Environment environment) {
        boolean production = java.util.Arrays.asList(environment.getActiveProfiles()).contains("prod");
        if (secretKeyStr == null || secretKeyStr.isBlank()) {
            if (production) {
                throw new IllegalStateException(
                        "security.identity.hmac-secret is not set under the 'prod' profile. Service-to-service "
                        + "identity would be signed with a publicly known development key. Set the "
                        + "IDENTITY_HMAC_SECRET environment variable.");
            }
            LOG.warn("security.identity.hmac-secret is not set; falling back to the development key. "
                    + "Set IDENTITY_HMAC_SECRET before any non-development use.");
            secretKeyStr = DEV_SECRET;
        } else if (DEV_SECRET.equals(secretKeyStr) && production) {
            throw new IllegalStateException(
                    "security.identity.hmac-secret is the publicly known development key and the 'prod' "
                    + "profile is active. Set IDENTITY_HMAC_SECRET to a private value.");
        }
        
        this.secretKey = secretKeyStr.getBytes(StandardCharsets.UTF_8);
    }

    public String sign(String userId, String roles, String phone, String sessionId, long issuedAt) {
        // userId|roles|phone|sessionId|issuedAt
        String payload = String.format("%s|%s|%s|%s|%d", 
            userId != null ? userId : "",
            roles != null ? roles : "",
            phone != null ? phone : "",
            sessionId != null ? sessionId : "",
            issuedAt);
            
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "HmacSHA256");
            mac.init(secretKeySpec);
            byte[] signatureBytes = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate identity signature", e);
        }
    }

    public boolean verify(String signatureBase64, String userId, String roles, String phone, String sessionId, long issuedAt) {
        if (signatureBase64 == null || signatureBase64.isBlank()) {
            return false;
        }
        
        String expectedSignature = sign(userId, roles, phone, sessionId, issuedAt);
        return expectedSignature.equals(signatureBase64);
    }
}
