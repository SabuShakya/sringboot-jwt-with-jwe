package com.sabu.springbootjwt;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

@SpringBootApplication
public class SpringbootJwtApplication {

    public static void main(String[] args) throws JOSEException {
        SpringApplication.run(SpringbootJwtApplication.class, args);

        // TO GENERATE RSA KEY
        RSAKey rsaKey = new RSAKeyGenerator(2048).generate().toRSAKey();
        rsaKey.toRSAKey();
    }

}
