import java.math.BigInteger;

/**
 * 
 * Represents the Cipher containing the ephemeral key and ciphertext
 *
 */
public class Cipher {
  private BigInteger ke;
  private BigInteger ctext;

  public Cipher(BigInteger ke, BigInteger ctext) {
    this.ke = ke;
    this.ctext = ctext;
  }

  public BigInteger getKe() {
    return ke;
  }

  public BigInteger getCtext() {
    return ctext;
  }
}