package com.sabu.springbootjwt.factory;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;

@Slf4j
@Component
public class KeyFactory {

//    private final static String RSA_KEY = "12sdasdasdjahsdahsd";
//    private final static String AES_SECRET_KEY = "7sdadjah4s1dahsd";

    @Value("${rsaKey}")
    private String rsaKey;

    @Value("${aesSecretKey}")
    private String aesSecretKey;

    public RSAKey getRSASignerKey() {

        RSAKey key = null;
        try {
            key = RSAKey.parse(rsaKey);
        } catch (ParseException e) {
            log.error("Error generating rsa key ", e);
        }
        return key;
    }

    public SecretKey getAESEncryptorKey() throws NoSuchAlgorithmException {
        int keyBitLength = EncryptionMethod.A128CBC_HS256.cekBitLength();

        // Generate key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keyBitLength);
        SecretKey key = keyGen.generateKey();
        System.out.println("========>"+key.toString());
        return key;
//        return new SecretKeySpec(aesSecretKey.getBytes(), "AES");
    }
}
