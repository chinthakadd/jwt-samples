package com.chinthakad.jwt.samples;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.Date;
import java.util.Objects;

public class JwtSample {

    public static void main(String[] args) throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException, UnrecoverableKeyException, JOSEException {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(JOSEObjectType.JWT)
                .build();

        JWTClaimsSet payload = new JWTClaimsSet.Builder()
                .issuer("me")
                .audience("you")
                .subject("bob")
                .expirationTime(Date.from(Instant.now().plusSeconds(120)))
                .build();

        JWSObject jwsObj = new JWSObject(header
                , new Payload(payload.toJSONObject()));


        String jksPassword = "changeme";
        KeyStore ks = KeyStore.getInstance("jks");
        ks.load(JwtSample.class.getClassLoader().getResourceAsStream("default.jks"), jksPassword.toCharArray());
        RSAPrivateKey key = (RSAPrivateKey) ks.getKey("hanbotest", jksPassword.toCharArray());

        Objects.requireNonNull(key);

        RSASSASigner rsassaSigner = new RSASSASigner(key);
        jwsObj.sign(rsassaSigner);

        System.out.println(jwsObj.serialize());
    }
}
