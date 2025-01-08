package com.verygood.security.configuration;

import com.verygood.security.component.SoapSigner;
import com.verygood.security.domain.SoapSignerContext;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Objects;
import lombok.extern.slf4j.Slf4j;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.Merlin;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Slf4j
@Configuration
public class SecurityConfig {

  @Value("${service.security.keystore.location:keystore/signing-keystore.jks}")
  private String keystoreLocation;

  @Value("${service.security.keystore.alias:emsnewcert}")
  private String keystoreAlias;

  @Value("${service.security.keystore.password:emsnewpassword1}")
  private String keystorePassword;

  @Value("${service.security.keystore.private-key-password:emsnewpassword2}")
  private String keystorePrivateKeyPassword;

  @Bean
  public Crypto getCrypto() {
    final ClassLoader classLoader = this.getClass().getClassLoader();
    try (InputStream inputStream = classLoader.getResourceAsStream(keystoreLocation)){
      final byte[] keyStoreBytes = Objects.requireNonNull(inputStream).readAllBytes();
      Merlin merlin = new Merlin();
      merlin.setKeyStore(getKeyStore(keyStoreBytes, keystorePassword));
      return merlin;
    } catch (IOException e) {
      log.error("Error while reading keystore file", e);
      throw new RuntimeException(e);
    }
  }

  public KeyStore getKeyStore(byte[] keyStoreBytes, String keystorePassword) {
    try (InputStream is = new ByteArrayInputStream(keyStoreBytes)) {
      KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
      keyStore.load(is, keystorePassword.toCharArray());
      return keyStore;
    } catch (KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException e) {
      log.error("Error while parsing keystore", e);
      throw new RuntimeException("Could not parse keystore for signing SOAP message.", e);
    }
  }

  @Bean
  public SoapSigner soapSigner(Crypto crypto) {
    SoapSignerContext context = SoapSignerContext.builder()
      .crypto(crypto)
      .keystoreAlias(keystoreAlias)
      .keystorePrivateKeyPassword(keystorePrivateKeyPassword)
      .build();
    return new SoapSigner(context);
  }

}
