package com.verygood.security.configuration;

import com.verygood.security.component.SoapSigner;
import java.util.Properties;
import lombok.SneakyThrows;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

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
  @SneakyThrows
  public Crypto getCrypto() {
    Properties properties = new Properties();
    properties.setProperty("org.apache.ws.security.crypto.merlin.keystore.type", "jks");
    properties.setProperty("org.apache.ws.security.crypto.merlin.file", keystoreLocation);
    properties.setProperty("org.apache.ws.security.crypto.merlin.keystore.alias", keystoreAlias);
    properties.setProperty("org.apache.ws.security.crypto.merlin.keystore.password", keystorePassword);

    return CryptoFactory.getInstance(properties);
  }

  @Bean
  public SoapSigner soapSigner(Crypto crypto) {
    final ClassPathResource securityPolicy = new ClassPathResource("soap/server-security-policy.xml");
    return new SoapSigner(securityPolicy, crypto, keystoreAlias, keystorePrivateKeyPassword);
  }

}
