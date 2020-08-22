# Keystore and Truststore Generation Commands


1. Create JKS with RSA2048 Private Key

keytool -genkey -alias com.chinthakad -keyalg RSA -keystore default.jks -keysize 2048

2. Create Public Certificate from the JKS

keytool -export -keystore default.jks -alias com.chinthakad -file chinthakad-jwt-signer.cer

3. Create a Truststore with teh CER

keytool -import -alias com.chinthakad -keystore chinthaka-jwt-truststore -storepass changeme
