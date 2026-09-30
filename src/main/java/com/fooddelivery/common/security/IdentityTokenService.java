package com.fooddelivery.common.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Service
public class IdentityTokenService {

    /** Retained only to reject installations that previously used this public value. */
    static final String DEV_SECRET = "dev-only-insecure-identity-hmac-secret-override-in-production-12";

    private final byte[] secretKey;

    public IdentityTokenService(
            @Value("${security.identity.hmac-secret:${IDENTITY_HMAC_SECRET:}}") String secretKeyStr,
            org.springframework.core.env.Environment environment) {
        if (secretKeyStr == null || secretKeyStr.isBlank()) {
            throw new IllegalStateException(
                    "security.identity.hmac-secret is required. Set the IDENTITY_HMAC_SECRET environment variable "
                    + "to a private value before starting any service.");
        }
        if (DEV_SECRET.equals(secretKeyStr)) {
            throw new IllegalStateException(
                    "security.identity.hmac-secret is a publicly known development key. Set IDENTITY_HMAC_SECRET "
                    + "to a private value.");
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
        return java.security.MessageDigest.isEqual(
                expectedSignature.getBytes(StandardCharsets.UTF_8),
                signatureBase64.getBytes(StandardCharsets.UTF_8));
    }
}
