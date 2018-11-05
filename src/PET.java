import java.io.*;
import java.math.BigInteger;
import java.util.Random;
import java.security.SecureRandom;

public class PET {

  public static void main(String[] args) {
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
    BigInteger i1 = Crypto.RandomInRange(BigInteger.TWO, p.subtract(BigInteger.ONE));
    System.out.println("i1 is " + i1);
    Elgamal player2 = new Elgamal(p, g2, d2);
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