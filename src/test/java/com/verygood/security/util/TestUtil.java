package com.verygood.security.util;

import java.io.IOException;
import lombok.experimental.UtilityClass;
import org.springframework.core.io.ClassPathResource;

@UtilityClass
public class TestUtil {

  public byte[] readResourceFromClasspath(String resourceFilePath) throws IOException {
    final ClassPathResource resource = new ClassPathResource(resourceFilePath);
    return resource.getInputStream().readAllBytes();
  }
}
