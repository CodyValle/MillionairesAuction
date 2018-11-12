import java.math.BigInteger;
import java.util.Random;

import org.bouncycastle.jce.provider.*;

import java.security.Security;
import java.security.SecureRandom;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

// From: http://tutorials.jenkov.com/java-cryptography/index.html
// From: https://gist.github.com/dmydlarz/32c58f537bb7e0ab9ebf
// From: http://www.java2s.com/Tutorial/Java/0490__Security/ElGamalexamplewithrandomkeygeneration.htm

// BouncyCastle docs: https://people.eecs.berkeley.edu/~jonah/bc/overview-summary.html

public class BouncyCastleTut {
    public static void main(String[] args) {
        /// Perform RSA encryption
        RSAExample();
        System.out.println();

        /// Perform ElGamal encryption
        ElGamalExample();
        System.out.println();
    }

    public static void ElGamalExample() {
      System.out.println("ElGamal Example");
      try {
        /*
        The Provider (java.security.Provider) class is a central class in the 
        Java cryptography API. In order to use the Java crypto API you need a 
        Provider set. The Java SDK comes with its own cryptography provider. 
        If you don't set an explicit cryptography provider, the Java SDK 
        default provider is used. However, this provider may not support the 
        encryption algorithms you want to use. Therefore you might have to set 
        your own cryptography provider.
        */
        Security.addProvider(new BouncyCastleProvider());

        // Generate public and private keys
        final int keySize = 2048;
        KeyPairGenerator generator = KeyPairGenerator.getInstance("ElGamal", "BC"); // BC for BouncyCastle
        
        SecureRandom random = new SecureRandom();
        generator.initialize(keySize, random);

        KeyPair pair = generator.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();

        System.out.println("Public Key: " + publicKey);
        System.out.println("Private Key: " + privateKey); // Can't print out the private key

        // Broadcast the public key somehow...

        // Encrypt a message using the public key
        String message = "Launch the missile.";
        Cipher cipher = Cipher.getInstance("ElGamal/None/NoPadding", "BC"); // BC for BouncyCastle
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, random);
        byte[] cipherText = cipher.doFinal(message.getBytes());
        System.out.println("Ciphertext: " + new String(cipherText));

        // Send the ciphertext back
        
        // Decrypt the message
        cipher.init(Cipher.DECRYPT_MODE, privateKey); // Here we are using the same Cipher, since their creation is expensive.
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("Decrypted: " + new String(plainText));
      }
      catch (Exception e) {
        System.out.println("Caught exception: " + e);
      }
    }

    public static void RSAExample() {
      System.out.println("RSA Example");
      try {
        // Generate public and private keys
        final int keySize = 2048;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        System.out.println("Public Key: " + publicKey);
        System.out.println("Private Key: " + privateKey); // Can't print out the private key

        // Broadcast the public key somehow...

        // Encrypt a message with the public key
        String message = "This is a secret message";
        Cipher encCipher = Cipher.getInstance("RSA");
        encCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherText = encCipher.doFinal(message.getBytes());
        System.out.println("Ciphertext: " + new String(cipherText)); // Prints some junk.

        // Send the ciphertext back
        
        // Decrypt the message
        Cipher decCipher = Cipher.getInstance("RSA");
        decCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decrypted = decCipher.doFinal(cipherText);
        System.out.println("Decrypted: " + new String(decrypted)); // Prints "This is a secret message"
      }
      catch (Exception e) {
        System.out.println("Caught exception: " + e);
      }
    }
}