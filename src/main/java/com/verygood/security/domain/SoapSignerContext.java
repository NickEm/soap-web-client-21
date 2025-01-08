package com.verygood.security.domain;

import lombok.Builder;
import lombok.Builder.Default;
import lombok.Value;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.validate.SignatureTrustValidator;

@Value
@Builder
public class SoapSignerContext {

  Crypto crypto;
  String keystoreAlias;
  String keystorePrivateKeyPassword;
  @Default
  WSSConfig wssConfig = createWssConfig();
  @Default
  boolean includeTimestamp = false;

  private static WSSConfig createWssConfig() {
    WSSConfig config = WSSConfig.getNewInstance();
    config.setValidator(WSConstants.SIGNATURE, new SignatureTrustValidator());
    return config;
  }

}
