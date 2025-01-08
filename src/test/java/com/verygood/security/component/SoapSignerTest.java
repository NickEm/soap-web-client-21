package com.verygood.security.component;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.verygood.security.util.TestUtil;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
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
  void signAndVerify() throws IOException {
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
    boolean debug = false;
    if (debug) {
      Path resourcePath = Paths.get("src/test/resources/soap-request-%s.xml".formatted(DATE_TIME_FORMATTER.format(LocalDateTime.now())));
      /*this stores the request payload in a file in the root project folder*/
      Files.write(resourcePath, signedMessage);
    }
    soapSigner.verify(signedMessage);
  }

  @Test
  void testVerifySuccess() throws IOException {
    final byte[] signedMessage = TestUtil.readResourceFromClasspath("soap-signer/soap-request-signed-correct.xml");
    soapSigner.verify(signedMessage);
  }

  @Test
  void testVerifyFailure() throws IOException {
    final byte[] signedMessage = TestUtil.readResourceFromClasspath("soap-signer/soap-request-signed-incorrect.xml");
    assertThatThrownBy(() -> {
      soapSigner.verify(signedMessage);
    }).isInstanceOf(RuntimeException.class)
      .hasMessageContaining("SOAP signature verification failed.");
  }

  private static Stream<Arguments> requestFilePathProvider() {
    return Stream.of(
      Arguments.of("soap-signer/new/soap-request-signed-new-inline-spain.xml"),
      Arguments.of("soap-signer/new/soap-request-signed-new-line-breaks-spain.xml"),

      Arguments.of("soap-signer/legacy/soap-request-signed-legacy-inline-portugal.xml"),
      Arguments.of("soap-signer/legacy/soap-request-signed-legacy-inline-spain.xml"),
      Arguments.of("soap-signer/legacy/soap-request-signed-legacy-inline-united-kingdom.xml"),
      Arguments.of("soap-signer/legacy/soap-request-signed-legacy-line-breaks-portugal.xml"),
      Arguments.of("soap-signer/legacy/soap-request-signed-legacy-line-breaks-spain.xml"),
      Arguments.of("soap-signer/legacy/soap-request-signed-legacy-line-breaks-united-kingdom.xml")
    );
  }

  @ParameterizedTest
  @MethodSource("requestFilePathProvider")
  public void verifySoapSignature(String filePath) throws IOException {
    final byte[] signedMessage = TestUtil.readResourceFromClasspath(filePath);
    soapSigner.verify(signedMessage);
  }

}