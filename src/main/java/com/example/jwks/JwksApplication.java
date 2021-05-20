package com.example.jwks;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

import java.text.ParseException;

@SpringBootApplication
public class JwksApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwksApplication.class, args);
    }

    @Bean
    public JWKSet jwkSet(Environment environment) throws JOSEException, ParseException {
        String pem = "-----BEGIN PRIVATE KEY-----\n"
                + environment.getRequiredProperty("pem.private.key.without.header.footer")
                + "\n-----END PRIVATE KEY-----";

        RSAKey.Builder builder = new RSAKey.Builder(JWK.parseFromPEMEncodedObjects(pem).toRSAKey());
        builder.algorithm(JWSAlgorithm.RS256);
        builder.keyUse(KeyUse.SIGNATURE);
        builder.keyID("keyID");

        return new JWKSet(builder.build());
    }

}
