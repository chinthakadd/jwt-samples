package com.chinthakad.jwt.samples;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.Objects;

public class JwtValidation {

    public static void main(String[] args) throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException, UnrecoverableKeyException, JOSEException, ParseException {
        // =====================
        // SIGNATURE
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(JOSEObjectType.JWT)
                .build();

        JWTClaimsSet payload = new JWTClaimsSet.Builder()
                .issuer("me")
                .audience("you")
                .subject("bob")
                .expirationTime(Date.from(Instant.now().minusSeconds(5)))
                .build();

        JWSObject jwsObj = new JWSObject(header, new Payload(payload.toJSONObject()));

        String jksPassword = "changeme";
        KeyStore ks = KeyStore.getInstance("jks");
        ks.load(JwtSample.class.getClassLoader().getResourceAsStream("default.jks"), jksPassword.toCharArray());
        RSAPrivateKey key = (RSAPrivateKey) ks.getKey("com.chinthakad", jksPassword.toCharArray());

        Objects.requireNonNull(key);

        RSASSASigner rsassaSigner = new RSASSASigner(key);
        jwsObj.sign(rsassaSigner);


        // =====================
        // VALIDATION
        String jwt = jwsObj.serialize();

        ks.load(JwtSample.class.getClassLoader().getResourceAsStream("default.jks"), jksPassword.toCharArray());
        RSAPublicKey publicKey = (RSAPublicKey) ks.getCertificate("com.chinthakad").getPublicKey();

        assert publicKey != null;
        RSAKey rsaKey = new RSAKey.Builder(publicKey).build();
        JWSVerifier verifier = new RSASSAVerifier(rsaKey);
        JWSObject jwtObj = JWSObject.parse(jwt);
        System.out.println(jwtObj.verify(verifier));
        System.out.println(jwtObj.getPayload().toJSONObject().toJSONString());

    }
}
