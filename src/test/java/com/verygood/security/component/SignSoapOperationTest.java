package com.verygood.security.component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;
import org.apache.commons.io.FilenameUtils;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;

@SpringBootTest
class SignSoapOperationTest {

  @Autowired
  private SignSoapOperation signSoapOperation;

  private static Stream<Arguments> requestFilePathProvider() {
    return Stream.of(
      /*TODO: 2 firsts results in incorrect value, because they are formatted and not raw*/
      Arguments.of("sign-soap-operation/soap-request-signed-new-token-break.xml"),
      Arguments.of("sign-soap-operation/soap-request-signed-old-signature-break.xml"),
      Arguments.of("sign-soap-operation/soap-request-signed-new-token-break-raw.xml")
    );
  }

  @ParameterizedTest
  @MethodSource("requestFilePathProvider")
  public void alignLineBreaks(String filePath) throws IOException {
    final ClassPathResource resource = new ClassPathResource(filePath);
    final byte[] signedMessage = resource.getInputStream().readAllBytes();
    final byte[] bytes = signSoapOperation.alignLineBreaks(signedMessage);
    final String name = FilenameUtils.getName(filePath);
    Path resourcePath = Paths.get("src/test/resources/%s/%s".formatted("sign-soap-operation-output", name));
    Files.write(resourcePath, bytes);
  }
}