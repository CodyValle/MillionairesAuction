import org.bouncycastle.jce.provider.*;

import java.math.BigInteger;

import java.security.*;
import java.security.SecureRandom;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.IllegalBlockSizeException;

public class Player {

  private PrivateKey privateKey;
  private PublicKey publicKey;
  private byte[] message = new byte[0];

  public Player(String message) {
    this.message = message.getBytes();
  }

  public void initializeElGamal(DHParameterSpec elParams) {
    try {
      // Generate public and private keys
      KeyPairGenerator generator = KeyPairGenerator.getInstance("ElGamal", BouncyCastleProvider.PROVIDER_NAME);
      generator.initialize(elParams);

      KeyPair pair = generator.generateKeyPair();
      privateKey = pair.getPrivate();
      publicKey = pair.getPublic();
    }
    catch (Exception e) {
      System.out.println("Caught exception: " + e);
    }
  }

  public PublicKey getPublicKey() {
    return publicKey;
  }

  public void print1Encryption(BigInteger modulus) {
    byte[] one = new byte[1];
    one[0] = 0x01;
    try {
      Cipher cipher = Cipher.getInstance("ElGamal/None/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
      cipher.init(Cipher.ENCRYPT_MODE, publicKey);
      byte[] encrypted1 = cipher.doFinal(one);
      System.out.println("Encrypted 1: " + new BigInteger(encrypted1).mod(modulus).toString(16));
    }
    catch (Exception e) {
      System.out.println("Caught exception: " + e);
    }
  }

  public byte[] encryptWith(PublicKey publicKey, BigInteger p) {
    System.out.println("Encoding with: " + new String(message) + " (" + new BigInteger(message).mod(p).toString(16) + ")");
    try {
      Cipher cipher = Cipher.getInstance("ElGamal/None/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
      cipher.init(Cipher.ENCRYPT_MODE, publicKey);
      return cipher.doFinal(message);
    }
    catch (Exception e) {
      System.out.println("Caught exception: " + e);
    }

    return new byte[0];
  }

  public byte[] encrypt(BigInteger p) {
    System.out.println("Encoding: " + new String(message) + " (" + new BigInteger(message).mod(p).toString(16) + ")");
    try {
      Cipher cipher = Cipher.getInstance("ElGamal/None/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
      cipher.init(Cipher.ENCRYPT_MODE, publicKey);
      System.out.println("Cipher output size is " + (cipher.getOutputSize(message.length) * 8) + " bits.");
      return cipher.doFinal(message);
    }
    catch (Exception e) {
      System.out.println("Caught exception: " + e);
    }

    return new byte[0];
  }

  public byte[] decrypt(byte[] cipherText) {
    try {
      Cipher decCipher = Cipher.getInstance("ElGamal/None/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
      decCipher.init(Cipher.DECRYPT_MODE, privateKey);
      return decCipher.doFinal(cipherText);
    }
    catch (Exception e) {
      System.out.println("Caught exception: " + e);
    }

    return new byte[0];
  }
}