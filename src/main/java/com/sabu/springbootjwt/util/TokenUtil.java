package com.sabu.springbootjwt.util;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.jdi.request.InvalidRequestStateException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.UUID;

@Slf4j
@Component
public class TokenUtil {

    private final RSAKey signingKey;
    private final SecretKey encryptionKey;

    public TokenUtil(RSAKey signingKey, SecretKey encryptionKey) {
        this.signingKey = signingKey;
        this.encryptionKey = encryptionKey;
    }

    public String generateToken(UserDetails userDetails) throws Exception {
        Date now = new Date();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(userDetails.getUsername())
                .subject(userDetails.getUsername())
                .expirationTime(new Date(now.getTime() + 1000 * 60 * 10)) // expires in 10 minutes
                .notBeforeTime(now)
                .issueTime(now)
                .jwtID(UUID.randomUUID().toString())
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.getKeyID()).build(),
                claims);

        signedJWT.sign(new RSASSASigner(signingKey));

        JWEObject jweObjectOutput = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM).contentType("JWT").build(),
                new Payload(signedJWT));

        jweObjectOutput.encrypt(new DirectEncrypter(encryptionKey));

        String encryptedJWT = jweObjectOutput.serialize();

        return encryptedJWT;
    }

    public JWTClaimsSet parseEncryptedToken(String jweString) throws Exception {
        RSAKey senderPublicJWK = signingKey.toPublicJWK();

        JWEObject jweObject = JWEObject.parse(jweString);

        jweObject.decrypt(new DirectDecrypter(encryptionKey));

        JWSVerifier verifier = new RSASSAVerifier(senderPublicJWK);
//        Payload payload = jweObject.getPayload();

        SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();

        if (!signedJWT.verify(verifier)) {
            log.error("JWT TOKEN EXCEPTION: Signature is not valid");
            throw new InvalidRequestStateException("Token is invalid");
        }
        return signedJWT.getJWTClaimsSet();
    }

    private Boolean isTokenExpired(JWTClaimsSet jwtClaimsSet) {
        return jwtClaimsSet.getExpirationTime().before(new Date());
    }

    public Boolean validateToken(JWTClaimsSet jwtClaimsSet, UserDetails userDetails) {
        final String username = jwtClaimsSet.getSubject();
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(jwtClaimsSet));
    }

}

