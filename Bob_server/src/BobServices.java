
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

public class BobServices {


    private String message = "This is cipherText";
    private Socket socket            = null;
    private DataInputStream input   = null;
    private DataOutputStream out     = null;
    private String address = "127.0.0.1";
    private int port = 9090;

    private KeyPair RSAKey;
    private Key pub;
    private Key pvt;



    private File dataFile =  new File("D:\\cryptographyProject\\Bob_server\\src\\dataFile");
    private File signFile = new File("D:\\cryptographyProject\\Bob_server\\src\\signFile");
    private File keyFile  = new File("D:\\cryptographyProject\\Bob_server\\src\\keyFile");
    private byte[] signature;

    byte[] cipherText;
//    private String AES128Key ;
//    private double mod = 3.402823669209385e+38;

    int p = 23;
    int g = 9;
    int a = 4;
    double A = 0;
    double DHres = 0;

    SecretKey AES128key ;
    byte[] IV ;


    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";


    public void run() throws Exception {
        // establish a connection
        try
        {
            socket = new Socket(address, port);
            System.out.println("Connected");
            System.out.println("Bob is ready ");
            // takes input from terminal
            input  = new DataInputStream(System.in);

            // sends output to the socket
            out    = new DataOutputStream(socket.getOutputStream());
        }
        catch(UnknownHostException u)
        {
            System.out.println(u);
        }
        catch(IOException i)
        {
            System.out.println(i);
        }

        // string to read message from input
        String line = "";
        Base64.Encoder encoder = Base64.getEncoder();
        int counter = 0 ;
        // keep reading until "Over" is input
        while (!line.equals("Over"))
        {
            try
            {
                switch (counter){
                    case 0:
                        System.out.println("First Step:Generating two keys with RsA algorithm");
                        System.out.println("Do you want to generate Keys?");
                        line = input.readLine();
                        if(line.equals("yes")) {
                            KeyGenerator();
                            out.writeUTF("wait for RSA Keys");
                            System.out.println();
                            System.out.println("keys generated:");

                            System.out.println("public key is :" + encoder.encodeToString(pub.getEncoded()) );
                            System.out.println("private key is : " + encoder.encodeToString(pvt.getEncoded()));
                            saveKeyToFile();
                            System.out.println("Bob Save key to File");
                            System.out.println();
                        }
                        else
                            line = "Over";

                        break;

                    case 1:
                        System.out.println("************************************");
                        System.out.println("Do you want to Bob Authenticate to Alice?");
                        line = input.readLine();
                        if(line.equals("yes")){
                            System.out.println("Wait for Bob to Sign");
                            Sign();
                            System.out.println("Bob successfully signed the DATA");
                            out.writeUTF("Bob Signed The Data");
                            System.out.println();
                        }
                        else
                            line = "Over";
                        break;


                    case 2:
                        System.out.println("************************************");
                        System.out.println("Do you want to share The DATA and Sign path to Alice?");
                        line = input.readLine();
                        if(line.equals("yes")) {
                            out.writeUTF("wait for Data And sign paths");
                            out.writeUTF(dataFile.getAbsolutePath());
                            System.out.println("data path is :" + dataFile.getAbsolutePath());
                            out.writeUTF(signFile.getAbsolutePath());
                            System.out.println("sign path is :" + signFile.getAbsolutePath());
                            System.out.println("and Bob sends his Public key path too");
                            out.writeUTF(keyFile.getAbsolutePath());
                            System.out.println();
                        }
                        else
                            line = "Over";
                        break;

                    case 3:
                        System.out.println("************************************");
                        System.out.println("Do you want to share Symmetric key with Alice with diffie Helman algorithm?");
                        line = input.readLine();
                        if(line.equals("yes")) {
                           out.writeUTF("wait for generating Symmetric Key from Bob with DH algorithm");
                            DiffieHelman();
                            out.writeUTF(String.valueOf(A));
                            out.writeUTF(String.valueOf(g));
                            out.writeUTF(String.valueOf(p));
                            System.out.println("wait for getting g^b");
                            String gpowerb = getgpowerb();
                            DHres = Math.pow(Double.parseDouble(gpowerb) , a)%p;
//                            AES128Key = generateAESSecretKey();
//                            System.out.println("AES key is : " + AES128Key);
//                            System.out.println(Integer.toBinaryString(Integer.parseInt(AES128Key)));
//                            out.writeUTF(AES128Key);
                            System.out.println("DH key generated");
                            System.out.println();
                        }
                        else
                            line = "Over";
                        break;

                    case 4:
                        System.out.println("************************************");
                        System.out.println("Do you want to send message to alice nad encrypt it with AES128 in CBC mode?");
                        line = input.readLine();
                        if(line.equals("yes")) {
                            ConvertToAESKey();
                            ShowAesKey();
                            out.writeUTF("Bob Is  Sending encrypted message");
                            System.out.println("eneter messege:");
                            line = input.readLine();
                            while (!line.equals("end")) {
                                out.writeUTF(line);
                                 AES128Enc(line);
//                                String str = new String(IV, "UTF-8");
//                                System.out.println(IV.length);
//                                out.writeUTF(str);
//                                out.writeUTF(encryptedMessage);
                                out.write(IV);
                                out.write(cipherText);
                                line = input.readLine();
                            }
                            out.writeUTF("end");
                        }
                        else
                            line = "Over";

                        break;

                    default:
                            line = "Over";
                            out.writeUTF(line);

                }


                counter ++ ;
//
//                line = input.readLine();
//                out.writeUTF(line);
            }
            catch(IOException i)
            {
                System.out.println(i);
            }
        }

        // close the connection
        try
        {
            input.close();
            out.close();
            socket.close();
        }
        catch(IOException i)
        {
            System.out.println(i);
        }

    }

    public void KeyGenerator() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        //key size 1024 or 2048 and 2048 is recommended in ssl
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        RSAKey = kp;
        pub = kp.getPublic();
        pvt = kp.getPrivate();
    }

    public void Sign() throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException {
        //signature algorithm “SHA256withRSA” is guaranteed to be supported on all JVMs.
        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initSign(RSAKey.getPrivate());
        InputStream in = null;
        try {
            in = new FileInputStream(dataFile);
            byte[] buf = new byte[2048];
            int len;
            while ((len = in.read(buf)) != -1) {
                sign.update(buf, 0, len);
            }
        } finally {
            if ( in != null ) in.close();
        }

        OutputStream out = null;
        try {
            out = new FileOutputStream(signFile);
            byte[] signature = sign.sign();
            out.write(signature);
        } finally {
            if ( out != null ) out.close();
        }


    }

    public void saveKeyToFile() throws IOException {
        OutputStream out = null;
        out = new FileOutputStream(keyFile + ".key");
        out.write(pvt.getEncoded());
        out.close();

        out = new FileOutputStream(keyFile + ".pub");
        out.write(pvt.getEncoded());
        out.close();
    }


    public static String  generateAESSecretKey() {
        KeyGenerator keyGen = null;
        try {
            /*
             * Get KeyGenerator object that generates secret keys for the
             * specified algorithm.
             */
            keyGen = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        /* Initializes this key generator for key size to 256. */
        keyGen.init(128);

        /* Generates a secret key */
        SecretKey secretKey = keyGen.generateKey();

        String encodedKey = Base64.getEncoder().encodeToString(
                secretKey.getEncoded());
//        System.out.println(encodedKey);

        return encodedKey;
    }


    public void DiffieHelman(){
        A = Math.pow(g,a) % p ;
    }
    public String getgpowerb() throws IOException, InterruptedException {
        TimeUnit.SECONDS.sleep(4);
        File file = new File("D:\\cryptographyProject\\Bob_server\\src\\gpowerb.txt");

        BufferedReader br = new BufferedReader(new FileReader(file));

        return br.readLine();
    }

    public void ConvertToAESKey(){

        byte[] decodedKey = Base64.getDecoder().decode(String.format("%22s", Integer.toBinaryString((int) DHres)).replace(' ', '0'));
        AES128key = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }
    public void ShowAesKey(){

        String encodedKey = Base64.getEncoder().encodeToString(AES128key.getEncoded());
        System.out.println("AES key is :" + encodedKey );
    }

    public String AES128Enc(String input) throws Exception {
        String enrypted = "";
        IV = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(IV);


        File file = new File("D:\\cryptographyProject\\Bob_server\\src\\IV.txt");
        OutputStream  os = new FileOutputStream(file);
        os.write(IV);
        os.close();
//        BufferedWriter writer = new BufferedWriter(new FileWriter("D:\\cryptographyProject\\Bob_server\\src\\IV.txt"));
//        writer.
//        File.WriteAllBytes("Foo.txt", arrBytes);
//        writer.write(String.valueOf(IV));
//        writer.close();


        System.out.println("Original Text  : "+input);
        cipherText = encrypt(input.getBytes(),AES128key , IV);
        enrypted = Base64.getEncoder().encodeToString(cipherText);
        System.out.println("Encrypted Text : "+ enrypted);

        return enrypted;

    }

    public static byte[] encrypt (byte[] plaintext,SecretKey key,byte[] IV ) throws Exception
    {
        //Get Cipher Instance
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        //Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");

        //Create IvParameterSpec
        IvParameterSpec ivSpec = new IvParameterSpec(IV);

        //Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        //Perform Encryption
        byte[] cipherText = cipher.doFinal(plaintext);

        return cipherText;
    }




}


