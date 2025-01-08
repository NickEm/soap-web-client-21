package com.verygood.security.component;

import com.verygood.security.domain.SoapSignerContext;
import jakarta.xml.soap.MessageFactory;
import jakarta.xml.soap.SOAPException;
import jakarta.xml.soap.SOAPMessage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import javax.xml.crypto.dsig.DigestMethod;
import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.w3c.dom.Document;

public class SoapSigner {
  private final SoapSignerContext context;

  public SoapSigner(SoapSignerContext context) {
    this.context = context;
  }

  public byte[] sign(byte[] message) {
    try {
      SOAPMessage soapMessage = MessageFactory.newInstance().createMessage(null, new ByteArrayInputStream(message));

      Document document = soapMessage.getSOAPBody().getOwnerDocument();

      WSSecHeader secHeader = new WSSecHeader(document);
      secHeader.insertSecurityHeader();

      checkCertificateForAlias();

      WSSecSignature signature = new WSSecSignature(secHeader);
      signature.setUserInfo(context.getKeystoreAlias(), context.getKeystorePrivateKeyPassword());
      signature.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
      signature.setDigestAlgo(DigestMethod.SHA1);
      signature.setSignatureAlgorithm(WSS4JConstants.RSA_SHA1);
      signature.build(context.getCrypto());

      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      soapMessage.writeTo(outputStream);
      return outputStream.toByteArray();
    } catch (SOAPException e) {
      throw new RuntimeException("Could not create SOAP message from original one.", e);
    } catch (WSSecurityException e) {
      throw new RuntimeException("Could not sign SOAP message.", e);
    } catch (IOException e) {
      throw new RuntimeException("Could not serialise SOAP message.", e);
    }
  }

  private void checkCertificateForAlias() throws WSSecurityException {
    CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
    cryptoType.setAlias(context.getKeystoreAlias());

    X509Certificate[] certificates = context.getCrypto().getX509Certificates(cryptoType);
    if (certificates == null || certificates.length == 0) {
      throw new IllegalStateException("No certificates found for alias: " + context.getKeystoreAlias());
    }
  }

  public void verify(byte[] message) {
    SOAPMessage soapMessage;
    try {
      soapMessage = MessageFactory.newInstance().createMessage(null, new ByteArrayInputStream(message));
    } catch (SOAPException | IOException e) {
      throw new RuntimeException("Could not create SOAP message from original one.", e);
    }

    try {
      Document document = soapMessage.getSOAPBody().getOwnerDocument();

      WSSecurityEngine securityEngine = new WSSecurityEngine();
      securityEngine.setWssConfig(context.getWssConfig());

      RequestData requestData = new RequestData();
      requestData.setSigVerCrypto(context.getCrypto());
      /* This flag is need for backward compatibility.
      If we want to check signature in the new code of the signed messages by legacy code */
      requestData.setDisableBSPEnforcement(true);
      /*TODO: Not sure if this is needed, makes no affect*/
      requestData.setCallbackHandler(null);

      WSHandlerResult handlerResult = securityEngine.processSecurityHeader(document, requestData);

      if (handlerResult == null || handlerResult.getResults() == null || handlerResult.getResults().isEmpty()) {
        throw new RuntimeException("SOAP signature verification failed. No security results found.");
      }
    } catch (SOAPException | WSSecurityException e) {
      throw new RuntimeException("SOAP signature verification failed.", e);
    }
  }

}
