package com.verygood.security.component;

import jakarta.xml.soap.MessageFactory;
import jakarta.xml.soap.SOAPMessage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.cert.X509Certificate;
import javax.xml.crypto.dsig.DigestMethod;
import lombok.SneakyThrows;
import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.w3c.dom.Document;

public class SoapSigner {

  /*TODO: EM Figure out security policy*/
  private final Resource securityPolicy;
  private final Crypto crypto;
  private final String keystoreAlias;
  private final String keystorePrivateKeyPassword;

  public SoapSigner(Resource securityPolicy, Crypto crypto,
                    @Value("${service.security.keystore.alias}") String keystoreAlias,
                    @Value("${service.security.keystore.private-key-password}") String keystorePrivateKeyPassword) {
    this.securityPolicy = securityPolicy;
    this.crypto = crypto;
    this.keystoreAlias = keystoreAlias;
    this.keystorePrivateKeyPassword = keystorePrivateKeyPassword;
  }

  @SneakyThrows
  public byte[] sign(byte[] message) {
    SOAPMessage soapMessage = MessageFactory.newInstance().createMessage(null, new ByteArrayInputStream(message));

    Document document = soapMessage.getSOAPBody().getOwnerDocument();

    WSSecHeader secHeader = new WSSecHeader(document);
    secHeader.insertSecurityHeader();

    checkCertificateForAlias();

    WSSecSignature signature = new WSSecSignature(secHeader);
    signature.setUserInfo(keystoreAlias, keystorePrivateKeyPassword);
    signature.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
    signature.setDigestAlgo(DigestMethod.SHA1);
    signature.setSignatureAlgorithm(WSS4JConstants.RSA_SHA1);
    signature.build(crypto);

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    soapMessage.writeTo(outputStream);
    return outputStream.toByteArray();
  }

  private void checkCertificateForAlias() throws WSSecurityException {
    CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
    cryptoType.setAlias(keystoreAlias);

    X509Certificate[] certificates = crypto.getX509Certificates(cryptoType);
    if (certificates == null || certificates.length == 0) {
      throw new IllegalStateException("No certificates found for alias: " + keystoreAlias);
    }
  }

  /*TODO: EM Introduce*/
  public void verify(byte[] message) {

  }


}
