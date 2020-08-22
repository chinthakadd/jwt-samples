package com.chinthakad.jwt.samples;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jose.proc.JWEKeySelector;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import java.text.ParseException;

public class JweAes128Sample {

    public static void main(String[] args) throws JOSEException, BadJOSEException, ParseException {

        // ==========================================================================================
        // Creating JWE

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("email", "abc@example.com")
                .claim("name", "Chinthaka Dharmasiri")
                .build();

        Payload payload = new Payload(claims.toJSONObject());

        JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256);

        // aes-128-cbc
        String secret = "841D8A6C80CBA4FCAD32D5367C18C53B";
        byte[] secretKey = secret.getBytes();
        DirectEncrypter encrypter = new DirectEncrypter(secretKey);

        // JWT Token Creation
        JWEObject jweObject = new JWEObject(header, payload);
        jweObject.encrypt(encrypter);
        String token = jweObject.serialize();

        System.out.println("== JWE");
        System.out.println(token);


        // ==========================================================================================
        // Reading JWE

        ConfigurableJWTProcessor<SimpleSecurityContext> jwtProcessor = new DefaultJWTProcessor<SimpleSecurityContext>();
        JWKSource<SimpleSecurityContext> jweKeySource = new ImmutableSecret<SimpleSecurityContext>(secretKey);
        JWEKeySelector<SimpleSecurityContext> jweKeySelector =
                new JWEDecryptionKeySelector<>(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256, jweKeySource);
        jwtProcessor.setJWEKeySelector(jweKeySelector);

        JWTClaimsSet claimsFromJwe = jwtProcessor.process(token, null);
        String email = (String) claimsFromJwe.getClaim("email");
        String name = (String) claimsFromJwe.getClaim("name");

        System.out.println("== DECRYPTED CLAIMS");
        System.out.println(name);
        System.out.println(email);
    }
}
