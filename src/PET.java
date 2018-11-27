import java.io.*;
import java.math.BigInteger;
import java.util.Random;

import java.security.Security;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;

import javax.crypto.spec.DHParameterSpec;
import javax.crypto.IllegalBlockSizeException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.generators.ElGamalParametersGenerator;
import org.bouncycastle.crypto.params.ElGamalParameters;

public class PET {

  public boolean checkEquality(Player player1, Player player2, BigInteger p) {
    // Have the players encrypt their messages using the other player's public key
    //byte[] p1CipherText = player1.encryptWith(player2.getPublicKey());
    //byte[] p2CipherText = player2.encryptWith(player1.getPublicKey());
    byte[] p1CipherText = player1.encrypt_ElGamal();
    byte[] p2CipherText = player2.encrypt_ElGamal();

    // Cut the ciphertexts in half. Alpha and beta.
    int half = p1CipherText.length / 2;

    byte[] p1Alpha = new byte[half];
    byte[] p1Beta = new byte[half];
    System.arraycopy(p1CipherText, 0, p1Alpha, 0, half);
    System.arraycopy(p1CipherText, half, p1Beta, 0, half);

    byte[] p2Alpha = new byte[half];
    byte[] p2Beta = new byte[half];
    System.arraycopy(p2CipherText, 0, p2Alpha, 0, half);
    System.arraycopy(p2CipherText, half, p2Beta, 0, half);

    // Convert the alphas and betas to BigIntegers
    BigInteger p1AlphaBI = new BigInteger(p1Alpha);
    BigInteger p1BetaBI = new BigInteger(p1Beta);
    BigInteger p2AlphaBI = new BigInteger(p2Alpha);
    BigInteger p2BetaBI = new BigInteger(p2Beta);
    System.out.println("p1Alpha: " + (p1AlphaBI));
    System.out.println("p1Beta: " + (p1BetaBI));
    System.out.println("p2Alpha: " + (p2AlphaBI));
    System.out.println("p2Beta: " + (p2BetaBI));

    // Each player computes epsilon and zeta
    BigInteger p1Epsilon = p1AlphaBI.multiply(p2AlphaBI.modInverse(p));
    BigInteger p1Zeta = p1BetaBI.multiply(p2BetaBI.modInverse(p));
    BigInteger p2Epsilon = p2AlphaBI.multiply(p1AlphaBI.modInverse(p)).modPow(BigInteger.TWO, p);
    BigInteger p2Zeta = p2BetaBI.multiply(p1BetaBI.modInverse(p)).modPow(BigInteger.TWO, p);
    System.out.println("p1Epsilon: " + (p1Epsilon));
    System.out.println("p1Zeta: " + (p1Zeta));
    System.out.println("p2Epsilon: " + (p2Epsilon));
    System.out.println("p2Zeta: " + (p2Zeta));

    // Compute gamma and delta
    BigInteger gammaBI = p1Epsilon.multiply(p2Epsilon).mod(p);
    BigInteger deltaBI = p1Zeta.multiply(p2Zeta).mod(p);
    byte[] gamma = gammaBI.toByteArray();
    byte[] delta = deltaBI.toByteArray();
    System.out.println("gamma value is " + gammaBI);
    System.out.println("gamma is " + Integer.toString(gamma.length) + " bytes long.");
    System.out.println("delta value is " + deltaBI);
    System.out.println("delta is " + Integer.toString(delta.length) + " bytes long.");

    // Make the PET ciphertext
    byte[] PETciphertext = new byte[p1CipherText.length];
    System.arraycopy(gamma, 0, PETciphertext, half - gamma.length, gamma.length);
    System.arraycopy(delta, 0, PETciphertext, p1CipherText.length - delta.length, delta.length);
    System.out.println("PETciphertext value is " + new BigInteger(PETciphertext));
    System.out.println("PETciphertext is " + Integer.toString(PETciphertext.length) + " bytes long.");

    // Decrypt the PET ciphertext
    byte[] p1decrypt = player1.decrypt(PETciphertext);
    byte[] p2decrypt = player2.decrypt(PETciphertext);
    System.out.println("p1decrypt value is " + new BigInteger(p1decrypt));
    System.out.println("p1decrypt is " + Integer.toString(p1decrypt.length) + " bytes long.");
    System.out.println("p2decrypt value is " + new BigInteger(p2decrypt));
    System.out.println("p2decrypt is " + Integer.toString(p2decrypt.length) + " bytes long.");

    // Debug statements
    System.out.println("Player1 ciphertext (length " + Integer.toString(p1CipherText.length) + ") is " + new String(p1CipherText));
    System.out.println("Player2 ciphertext (length " + Integer.toString(p2CipherText.length) + ") is " + new String(p2CipherText));

    System.out.println("Player1's message is " + new String(player2.decrypt(p1decrypt)));
    System.out.println("Player2's message is " + new String(player1.decrypt(p2decrypt)));

    return true;
  }

  public static void main(String[] args) {
    try {
      // Intialize the BouncyCastle provider
      Security.addProvider(new BouncyCastleProvider());

      // Set up 
      final int keySize = 256;
      System.out.println("Keysize bits: " + keySize);
      
      // This is slow. Fifteen minutes on my old machine
      ElGamalParametersGenerator gen = new ElGamalParametersGenerator();
      int certainty = 4;
      gen.init(keySize, certainty, new SecureRandom());
      ElGamalParameters PandG = gen.generateParameters();
      System.out.println("p is " + PandG.getP().toString(16));
      System.out.println("g is " + PandG.getG().toString(16));
      
      //BigInteger p = new BigInteger("e2a4f19cfb298034366a808256f5ebf0c31dd4db77d77fe8c6570c517269589c7d660a4c0a588a411bcadd7e930267da58ee58f0d63209d3a41adfb37a52f4d86269c684935b9e018240cb3a64650a65eb66ebdcb0d422c9143e14a417bd650248e3935c2dc3a0512b04edbece76ecc4260b33edc8e7b1e1a30aed862ce7a96a3259fdb89bbe508bec5afdae1c1f48d0055fd9e52a031e245637b60af1c3b5d948df4544d88eb23439ed56e3cd020b989c7c70d0d23e128fc68d967f852b333077c44e09c14dfe9035307f1ed1eddf856cfe00488f5f1181f69220487d6cb9413b05a9ab5300adbf89177820b9c075e99d956ea60a21067260c4a90f3975f1f7", 16);
      //BigInteger g = new BigInteger("7ad82ef479128bb322e4cb0457f0285ce8e7555ec930c8f3235d21f22e4dba417171995f25b94c0dc2bcb7253898a5c1ad390493edf3c67e3f6771ad98594e58c09325531296f9859b15cfbaf8b51a90548874294b1af3bb619df5ea8e3da702816f1239d364c7e0ea2d0217ea9be20f188365d21ece72d199ef63dd5e46584acc6dbcd876e1e90b710089f42a8a2d55d9ed59267fb2b4504adeff361f38b19aca62e7caa72e6f666d1c78aab56920d0cf4782e95bb248b2c0f3e559c861f48b4642d0e246f3c1ad5f3743ceeb48c211e595f8423172379db31469bbfa05c58c45835a69efbc632d21254c9b40ef0cf4362b6906a5b9ff328a0d4c4a725ca535", 16);
      DHParameterSpec elParams = new DHParameterSpec(PandG.getP(), PandG.getG(), keySize);

      // Two players
      Player player1 = new Player("Player");
      Player player2 = new Player("Player");

      // Initialize as ElGamal players
      player1.initializeElGamal(elParams);
      player2.initializeElGamal(elParams);

      // Instantiate a PET object and check equality
      PET pet = new PET();
      pet.checkEquality(player1, player2, PandG.getP());
    }
    catch (Exception e) {
      System.out.println("Caught exception: " + e);
    }
  }

  public static void main_old(String[] args) {
    /// Set up two ElGamal ciphers, (a, b) and (a', b'), of the respective messages m and m'.

    // Set up
		Random rand = new SecureRandom();
    int bitSize = 32;
    // TODO: For security reasons, we should use a safe prime, i.e. p = 2q + 1, where q is also a prime
    BigInteger p = new BigInteger("23");
    //BigInteger p = BigInteger.probablePrime(bitSize, rand);

    // Mesages (supposed to be private)
    BigInteger m1 = new BigInteger("15");
    BigInteger m2 = new BigInteger("15");
    
    // TODO: Implement a primitive element calculator
    // 2 is always a generator
    BigInteger g1 = new BigInteger("2");
    BigInteger g2 = new BigInteger("2");
    
		// Private ElGamal keys
    // Must be elements [2, ..., p-2]
    BigInteger d1 = Crypto.RandomInRange(BigInteger.TWO, p.subtract(BigInteger.TWO));
    System.out.println("d1 is " + d1);
    BigInteger d2 = Crypto.RandomInRange(BigInteger.TWO, p.subtract(BigInteger.TWO));
    System.out.println("d2 is " + d2);

    //BigInteger d2;
    //do {
    //  d2 = Crypto.RandomInRange(BigInteger.TWO, p.subtract(BigInteger.TWO));
    //} while (p.gcd(d2).compareTo(BigInteger.ONE) != 0);
    
    // Create ElGamal systems
    Elgamal player1 = new Elgamal(p, g1, d1);
    System.out.println("player1 priv key is " + SaM.SquareAndMultiply(g1, d1, p));
    BigInteger i1 = Crypto.RandomInRange(BigInteger.TWO, p.subtract(BigInteger.ONE));
    System.out.println("i1 is " + i1);
    Elgamal player2 = new Elgamal(p, g2, d2);
    System.out.println("player2 priv key is " + SaM.SquareAndMultiply(g2, d2, p));
    BigInteger i2 = Crypto.RandomInRange(BigInteger.TWO, p.subtract(BigInteger.ONE));
    System.out.println("i2 is " + i2);

    // Encrypt the messages
    Cipher c1 = player1.encrypt(m1, i1);
    System.out.println("c1.ctext is " + c1.getCtext());
    System.out.println("c1.ke is " + c1.getKe());
    Cipher c2 = player2.encrypt(m2, i2);
    System.out.println("c2.ctext is " + c2.getCtext());
    System.out.println("c2.ke is " + c2.getKe());
    
    /// Each player publishes a Pederson commitment.
    
    // TODO: Implement the Pederson commitment, which is unnecessary when we trust all parties to follow protocol

    /// Each player calculates and publishes their (epsilon, zeta) ciphertext.

    // Calculate the epsilons
    BigInteger[] er1 = c1.getCtext().divideAndRemainder(c2.getCtext());
    System.out.println("er1 is (" + er1[0] + ", " + er1[1] + ")");
    BigInteger[] er2 = c2.getCtext().divideAndRemainder(c1.getCtext());
    System.out.println("er2 is (" + er2[0] + ", " + er2[1] + ")");

    // Calculate the zetas
    BigInteger[] zr1 = c1.getKe().divideAndRemainder(c2.getKe());
    System.out.println("zr1 is (" + zr1[0] + ", " + zr1[1] + ")");
    BigInteger[] zr2 = c2.getKe().divideAndRemainder(c1.getKe());
    System.out.println("zr2 is (" + zr2[0] + ", " + zr2[1] + ")");

    /// Each player performs a proof of knowledge.

    // TODO: Do the proof after implementing the Pederson commitment.

    /// Each player decrypts (gamma, delta) = (product of all epsilon, product of all zeta).

    // Calculate gamma
    BigInteger gamma = er1[0].multiply(er2[0]).mod(p);
    System.out.println("gamma is " + gamma);

    // Calculate delta
    BigInteger delta = zr1[0].multiply(zr2[0]).mod(p);
    System.out.println("delta is " + delta);

    // Combine to a Cipher
    Cipher gd = new Cipher(gamma, delta);

    // Decrypt gamma and delta
    System.out.println("gd.ctext is " + gd.getCtext());
    System.out.println("gd.ke is " + gd.getKe());
    BigInteger mp1 = player1.decrypt(gd);
    BigInteger mp2 = player2.decrypt(gd);

    /// Test that the plaintext of (gamma, delta) is 1.
    if (mp1.compareTo(m1) == 0) {
      System.out.println("mp1 is the same as m1");
    }
    else {
      System.out.println("mp1 is not the same as m1");
    }
    if (mp2.compareTo(m2) == 0) {
      System.out.println("mp2 is the same as m2");
    }
    else {
      System.out.println("mp2 is not the same as m2");
    }
  }

}