import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

public class Main {

    public static void main(String[] args) throws Exception {
        AliceServices aliceServices = new AliceServices();
        aliceServices.run();
    }
}
