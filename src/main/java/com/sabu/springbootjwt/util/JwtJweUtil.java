package com.sabu.springbootjwt.util;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.stereotype.Service;

import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtJweUtil {

    private static RSAPublicKey publicKey;
    private static RSAPrivateKey privateKey;

    public JwtJweUtil() throws NoSuchAlgorithmException {
        GenerateKeys generateKeys = new GenerateKeys(2048);
        generateKeys.createKeys();
        publicKey = generateKeys.getRsaPublicKey();
        privateKey = generateKeys.getRsaPrivateKey();
    }

    public String createJWEToken(String subject) throws JOSEException, NoSuchAlgorithmException {
        Date now = new Date();

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .issuer(subject)
                .subject(subject)
                .audience(Arrays.asList("https://app-one.com", "https://app-two.com"))
                .expirationTime(new Date(now.getTime() + 1000 * 60 * 10)) // expires in 10 minutes
                .notBeforeTime(now)
                .issueTime(now)
                .jwtID(UUID.randomUUID().toString())
                .build();

        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM);

        // Create the encrypted JWT object
        EncryptedJWT jwt = new EncryptedJWT(header, jwtClaimsSet);

        // Create an encrypter with the specified public RSA key
        RSAEncrypter encrypter = new RSAEncrypter(publicKey);

        // Do the actual encryption
        jwt.encrypt(encrypter);

        // Serialise to JWT compact form
        String jwtString = jwt.serialize();
        System.out.println("ENCRYPTED TOKEN"+jwtString);
        return jwtString;
    }

    public void parseJweToken(String jwtString) throws ParseException, JOSEException, NoSuchAlgorithmException {

        EncryptedJWT jwt = EncryptedJWT.parse(jwtString);
        // Create a decrypter with the specified private RSA key
        RSADecrypter decrypter = new RSADecrypter(privateKey);
        // Decrypt
        jwt.decrypt(decrypter);

        // Retrieve JWT claims
        System.out.println(jwt.getJWTClaimsSet().getIssuer());
        ;
        System.out.println(jwt.getJWTClaimsSet().getSubject());
        System.out.println(jwt.getJWTClaimsSet().getAudience().size());
        System.out.println(jwt.getJWTClaimsSet().getExpirationTime());
        System.out.println(jwt.getJWTClaimsSet().getNotBeforeTime());
        System.out.println(jwt.getJWTClaimsSet().getIssueTime());
        System.out.println(jwt.getJWTClaimsSet().getJWTID());
    }
}