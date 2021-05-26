package com.example.jwks;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.Test;

import java.util.UUID;

public class GenerateKey {

    @Test
    public void generateSignatureKey() throws JOSEException {
        String json = new RSAKeyGenerator(4096)
                .algorithm(JWSAlgorithm.RS256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate()
                .toJSONString();

        System.out.println("RSAKey");
        System.out.println(json);
    }

    @Test
    public void generateKey() throws JOSEException {
        String json = new RSAKeyGenerator(4096)
                .algorithm(JWSAlgorithm.RS256)
                .keyID(UUID.randomUUID().toString())
                .generate()
                .toJSONString();

        System.out.println("RSAKey");
        System.out.println(json);
    }

}
