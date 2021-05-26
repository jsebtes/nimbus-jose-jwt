package com.example.jwks;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.time.Instant;
import java.time.LocalDate;
import java.util.*;
import java.util.stream.Collectors;

@RestController
public class JwkSetRestController {

    private final Random random;

    private final JWKSet jwkSet;

    @Autowired
    public JwkSetRestController(JWKSet jwkSet) {
        this.jwkSet = jwkSet;
        this.random = new Random();
    }

    @GetMapping("/jwks")
    public Map<String, Object> keys() {
        return this.jwkSet.toJSONObject();
    }

    @GetMapping(value = "/jwt"/*, produces = JWK.MIME_TYPE*/)
    public String jwt() throws JOSEException {
        return buildAndSignJwt(getSigJwk());
    }

    private JWK getSigJwk() {
        List<JWK> sigJwks = jwkSet.getKeys().stream()
                .filter(jwk -> jwk.getKeyUse() == null || jwk.getKeyUse().equals(KeyUse.SIGNATURE))
                .collect(Collectors.toList());
        if (sigJwks.size() == 1) {
            return sigJwks.get(0);
        }
        else {
            return sigJwks.get(random.nextInt(sigJwks.size()));
        }
    }

    private String buildAndSignJwt(JWK jwk) throws JOSEException {
        Objects.requireNonNull(jwk);
        Objects.requireNonNull(jwk.getAlgorithm());
        Objects.requireNonNull(jwk.getKeyID());

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.parse(jwk.getAlgorithm().getName()))
                .type(JOSEObjectType.JWT)
                .keyID(jwk.getKeyID())
                .build();

        JWTClaimsSet payload = new JWTClaimsSet.Builder()
                .issuer("https://www.me.com")
                .issueTime(Date.from(Instant.now()))
                .audience("https://www.you.com")
                .subject("johndoe@gmail.com")
                .expirationTime(Date.from(Instant.now().plusSeconds(120)))
                .claim("given_name", "John")
                .claim("family_name", "Doe")
                .claim("email", "johndoe@gmail.com")
                .claim("gender", "male")
                .claim("bithdate", LocalDate.of(1980, 1, 26).toString())
                .build();

        SignedJWT signedJWT = new SignedJWT(header, payload);
        signedJWT.sign(new DefaultJWSSignerFactory().createJWSSigner(jwk));
        return signedJWT.serialize();
    }

    @GetMapping(value = "/test")
    public String test() throws JOSEException, ParseException {
        JWK jwk = getSigJwk();
        String jwt = buildAndSignJwt(jwk);

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.parse(jwk.getAlgorithm().getName())).build();

        return Boolean.valueOf(SignedJWT.parse(jwt)
                .verify(new DefaultJWSVerifierFactory().createJWSVerifier(header, jwk.toRSAKey().toPublicKey()))).toString();
    }

    @GetMapping(value = "/test2")
    public String test2() throws JOSEException, ParseException, MalformedURLException, BadJOSEException {
        String jwt = buildAndSignJwt(getSigJwk());


// Create a JWT processor for the access tokens
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();

// Set the required "typ" header "at+jwt" for access tokens issued by the
// Connect2id server, may not be set by other servers
        jwtProcessor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(JOSEObjectType.JWT));

// The public RSA keys to validate the signatures will be sourced from the
// OAuth 2.0 server's JWK set, published at a well-known URL. The RemoteJWKSet
// object caches the retrieved keys to speed up subsequent look-ups and can
// also handle key-rollover
        JWKSource<SecurityContext> keySource = new RemoteJWKSet<>(new URL("http://localhost:8080/jwks"));

// The expected JWS algorithm of the access tokens (agreed out-of-band)
        JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;

// Configure the JWT processor with a key selector to feed matching public
// RSA keys sourced from the JWK set URL
        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(expectedJWSAlg, keySource);

        jwtProcessor.setJWSKeySelector(keySelector);

// Set the required JWT claims for access tokens issued by the Connect2id
// server, may differ with other servers
        jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                new JWTClaimsSet.Builder().issuer("https://www.me.com").build(),
                new HashSet<>(Arrays.asList("sub", "exp", "aud"))));

// Process the token
        SecurityContext ctx = null; // optional context parameter, not required here
        JWTClaimsSet claimsSet = jwtProcessor.process(jwt, ctx);

// Print out the token claims set
        return claimsSet.toJSONObject().toString();
    }

}
