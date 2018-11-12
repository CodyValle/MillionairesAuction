import java.math.BigInteger;
import java.util.Random;

public class Crypto {

  // Returns a (insecure) random BigInteger x, where min <= x <= max
  public static BigInteger RandomInRange(BigInteger min, BigInteger max) {
    return new BigInteger(max.bitLength(), new Random()).mod(max.subtract(min)).add(min);
  }

}