import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.SchemaOutputResolver;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Random;
import java.util.concurrent.TimeUnit;

public class AliceServices {
    //initialize socket and input stream
    private Socket socket   = null;
    private ServerSocket server   = null;
    private DataInputStream in       =  null;
    private int port = 9090;

    private Key pub;
    private Key pvt;
    private KeyPair RSAKEY;


    int b = 4;
    double  DHres = 0;

    SecretKey AES128key ;
    byte[] IV ;
    byte[] message  ;

    String encMes = "";

    public void run () throws Exception {
        try
        {
            server = new ServerSocket(port);
//            System.out.println("Server started");
//
//
//            System.out.println("Waiting for a client ...");
            System.out.println("Alice is ready and waiting for Bob");

            socket = server.accept();
//            System.out.println("Client accepted");
            System.out.println("Bob is ready too!");
            System.out.println("************************************");
            System.out.println();

            // takes input from the client socket
            in = new DataInputStream(
                    new BufferedInputStream(socket.getInputStream()));

            String line = "";

            // reads message from client until "Over" is sent
            while (!line.equals("Over"))
            {
                try
                {
                    line = in.readUTF();
                    System.out.println(line);
                    if(line.equals("wait for RSA Keys")){
                        System.out.println("generating public and private keys");
                        KeyGenerator();
                        System.out.println("public and private keys generated!");
                        Base64.Encoder encoder = Base64.getEncoder();
                        //encoder.encodeToString(pub.getPublic())
                        System.out.println("Alice public key is :" + encoder.encodeToString(pub.getEncoded()) );
                        System.out.println("Alice private key is : " + encoder.encodeToString(pvt.getEncoded()));
                        System.out.println();

                    }
                    if(line.equals("wait for Data And sign paths")){
                        //get datafile path
                        String datafilepath = in.readUTF();
                        String signpathfile = in.readUTF();
                        String BobPublicKey = in.readUTF();
//                        Authenticator(datafilepath  , signpathfile , BobPublicKey);
                    }



                    if(line.equals("wait for generating Symmetric Key from Bob with DH algorithm")){

                        String A = in.readUTF();
                        String g = in.readUTF();
                        String p = in.readUTF();
                        double B = Math.pow(Double.parseDouble(g),b)%(Double.parseDouble(p));
                        System.out.println("saving  g^b to file");
                        BufferedWriter writer = new BufferedWriter(new FileWriter("D:\\cryptographyProject\\Bob_server\\src\\gpowerb.txt"));
                        writer.write(String.valueOf(B));
                        writer.close();
                        DHres = Math.pow(Double.parseDouble(A),b)%(Double.parseDouble(p));
                        System.out.println("symmetric key shared with diffie hellman algorithm");
                        System.out.println();
                    }

                    if(line.equals("Bob Is  Sending encrypted message"))
                    {
                        ConvertToAESKey();
                        ShowAesKey();
                        System.out.println("waiting for bob");
                        encMes = in.readUTF();
                        while(!encMes.equals("end")){
//                            IV = in.readUTF().getBytes(StandardCharsets.UTF_8);
//                            System.out.println(IV.length);

                            IV = new byte[16];
                            message = new byte[16];
                             in.read(IV);
                            System.out.println(IV.toString());
                            in.read(message);
                             //"D:\\cryptographyProject\\Bob_server\\src\\Message.txt"
//                             FileInputStream is = new FileInputStream(file);
//                            DataInputStream dis = new DataInputStream(is);
//                            dis.read(IV);
//                            dis.close();
//                            is.close();

                            AES128DEC(message);
                            encMes = in.readUTF();
                        }
                    }




                }
                catch(IOException i)
                {
                    System.out.println(i);
                }
            }
            System.out.println("Closing connection");

            // close connection
            socket.close();
            in.close();
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
        RSAKEY = kp;
        pub = kp.getPublic();
        pvt = kp.getPrivate();
    }

    public String Authenticator(String DataPath , String SignPath  , String BobPublicKey) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, InvalidKeyException, SignatureException {
        Signature sign = Signature.getInstance("SHA256withRSA");
        /* Read all the public key bytes */
        byte[] bytes = Files.readAllBytes(Paths.get(BobPublicKey));

        /* Generate public key. */
        X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pub = kf.generatePublic(ks);
        sign.initVerify(pub);

        InputStream in = null;
        try {
            in = new FileInputStream(DataPath);
            byte[] buf = new byte[2048];
            int len;
            while ((len = in.read(buf)) != -1) {
                sign.update(buf, 0, len);
            }
        } finally {
            if ( in != null ) in.close();
        }

        /* Read the signature bytes from file */
        bytes = Files.readAllBytes(Paths.get(SignPath));
        System.out.println("dataFile" + ": Signature " +
                (sign.verify(bytes) ? "OK" : "Not OK"));
        String res = (sign.verify(bytes) ? "OK" : "Not OK");
        return res;
    }

    public void ConvertToAESKey(){
        byte[] decodedKey = Base64.getDecoder().decode(String.format("%22s", Integer.toBinaryString((int) DHres)).replace(' ', '0'));
        AES128key = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }
    public void ShowAesKey(){

        String encodedKey = Base64.getEncoder().encodeToString(AES128key.getEncoded());
        System.out.println("AES key is :" + encodedKey );
    }

    public String AES128DEC(byte [] input) throws Exception {
        String decrypted = "";
        System.out.println("Original Text  : " + input);
//        System.out.println(input.length);
        decrypted = decrypt(input,AES128key , IV);
        System.out.println("DeCrypted Text : "+decrypted);

        encMes = decrypted;
        return decrypted;
    }



    public static String decrypt (byte[] cipherText, SecretKey key,byte[] IV) throws Exception
    {
        //Get Cipher Instance
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        //Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");

        //Create IvParameterSpec
        IvParameterSpec ivSpec = new IvParameterSpec(IV);

        //Initialize Cipher for DECRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        //Perform Decryption
        byte[] decryptedText = cipher.doFinal(cipherText);

        return new String(decryptedText);
    }

}
