package com.verygood.security.component;

import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class SignSoapOperation {

  private final SoapSigner soapSigner;
  private final Boolean ignoreLineBreaks;


  public SignSoapOperation(@Autowired SoapSigner soapSigner,
                           @Value("${service.soap.ignore-line-breaks:true}") Boolean ignoreLineBreaks) {
    this.soapSigner = soapSigner;
    this.ignoreLineBreaks = ignoreLineBreaks;
  }

  public byte[] process(byte[] msg) {
    log.debug("Signing SOAP message");
    log.debug("Setup keystore callback");
    log.debug("Setup signer");
    log.debug("Signing...");
    byte[] signed = soapSigner.sign(msg);
    /*TODO: Fix ignore line breaks*/
    if (ignoreLineBreaks) {
      signed = alignLineBreaks(signed);
    }
    log.debug("SOAP message successfully signed");
    return signed;
  }

  public byte[] alignLineBreaks(byte[] message) {
    String alignedXml = new String(message);
    alignedXml = alignLineBreaksSignatureValue(alignedXml);
    alignedXml = alignLineBreaksSecurityTokenValue(alignedXml);
    return alignedXml.getBytes(StandardCharsets.UTF_8);
  }

  private String alignLineBreaksSignatureValue(String xml) {
    String tokenPattern = "(<ds:SignatureValue[^>]*>)(.*?)(</ds:SignatureValue>)";
    Pattern pattern = Pattern.compile(tokenPattern, Pattern.DOTALL);
    return alignLineBreaksTagValue(xml, pattern);
  }

  private String alignLineBreaksSecurityTokenValue(String xml) {
    String tokenPattern = "(<wsse:BinarySecurityToken[^>]*>)(.*?)(</wsse:BinarySecurityToken>)";
    Pattern pattern = Pattern.compile(tokenPattern, Pattern.DOTALL);
    return alignLineBreaksTagValue(xml, pattern);
  }

  private String alignLineBreaksTagValue(String xml, Pattern pattern) {
    Matcher matcher = pattern.matcher(xml);

    if (matcher.find()) {
      String startTag = matcher.group(1); // <wsse:BinarySecurityToken ...>
      String value = matcher.group(2);   // Content inside the tags
      String endTag = matcher.group(3);  // </wsse:BinarySecurityToken>

      String cleanedValue = value.replaceAll("&#13;\n", "");
      String cleanedToken = startTag + cleanedValue + endTag;
      xml = xml.replace(matcher.group(0), cleanedToken);
    }

    return xml;
  }

}
