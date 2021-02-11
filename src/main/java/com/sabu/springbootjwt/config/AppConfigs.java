package com.sabu.springbootjwt.config;

import com.nimbusds.jose.jwk.RSAKey;
import com.sabu.springbootjwt.factory.KeyFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

@Slf4j
@Configuration
public class AppConfigs {

    @Autowired
    private KeyFactory keyFactory;

    @Bean
    RSAKey signer() {
       return keyFactory.getRSASignerKey();
    }

    @Bean
    SecretKey encryptor() throws NoSuchAlgorithmException {
        return keyFactory.getAESEncryptorKey();
    }
}
