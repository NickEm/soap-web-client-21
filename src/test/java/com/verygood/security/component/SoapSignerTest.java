package com.verygood.security.component;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class SoapSignerTest {

  public static final DateTimeFormatter DATE_TIME_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

  @Autowired
  private SignSoapOperation signSoapOperation;

  @Autowired
  private SoapSigner soapSigner;

  @Test
  void sign() throws IOException {
    String soapMessage =
      """
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
          xmlns:gs="http://spring.io/guides/gs-producing-web-service">
            <soapenv:Header/>
            <soapenv:Body>
                <gs:getCountryRequest>
                    <gs:name>Spain</gs:name>
                </gs:getCountryRequest>
            </soapenv:Body>
        </soapenv:Envelope>
      """;
    final byte[] signedMessage = signSoapOperation.process(soapMessage.getBytes());

    final String stringified = new String(signedMessage, Charset.defaultCharset());
    System.out.println("=== +++ ===");
    System.out.println(stringified);
    System.out.println("=== +++ ===");
    Path resourcePath = Paths.get("src/test/resources/soap-request-%s.xml".formatted(DATE_TIME_FORMATTER.format(LocalDateTime.now())));
    /*this stores the request payload in a file in the root project folder*/
    Files.write(resourcePath, signedMessage);
  }

}