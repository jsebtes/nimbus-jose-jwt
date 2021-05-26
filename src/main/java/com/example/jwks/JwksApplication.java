package com.example.jwks;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
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
    public JWKSet jwkSet(Environment environment) throws ParseException {
        JWKSet jwkSet = new JWKSet(JWK.parse(environment.getRequiredProperty("jwk.json")));
        if (jwkSet.getKeys().stream().noneMatch(jwk -> jwk.getKeyUse() == null || jwk.getKeyUse().equals(KeyUse.SIGNATURE))) {
            throw new RuntimeException("No sig jwk");
        }
        return jwkSet;
    }

}
