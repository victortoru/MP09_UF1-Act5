import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class Utilitats {
    public static SecretKey keygenKeyGeneration(int keySize) {
        SecretKey sKey = null;
        if ((keySize == 128)||(keySize == 192)||(keySize == 256)) {
            try {
                KeyGenerator kgen = KeyGenerator.getInstance("AES");
                kgen.init(keySize);
                sKey = kgen.generateKey();

            } catch (NoSuchAlgorithmException ex) {
                System.err.println("Generador no disponible.");
            }
        }
        return sKey;
    }

    public static SecretKey passwordKeyGeneration(String text, int keySize) {
        SecretKey sKey = null;
        if ((keySize == 128)||(keySize == 192)||(keySize == 256)) {
            try {
                byte[] data = text.getBytes("UTF-8");
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] hash = md.digest(data);
                byte[] key = Arrays.copyOf(hash, keySize/8);
                sKey = new SecretKeySpec(key, "AES");
            } catch (Exception ex) {
                System.err.println("Error generant la clau:" + ex);
            }
        }
        return sKey;
    }

    public static byte[] encryptData(byte[] data, PublicKey pub) {
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding","SunJCE");
            cipher.init(Cipher.ENCRYPT_MODE, pub);
            encryptedData =  cipher.doFinal(data);
        } catch (Exception  ex) {
            System.err.println("Error xifrant: " + ex);
        }
        return encryptedData;
    }
    public static byte[] decryptData(byte[] data, PrivateKey pub) {
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding","SunJCE");
            cipher.init(Cipher.DECRYPT_MODE, pub);
            encryptedData =  cipher.doFinal(data);
        } catch (Exception  ex) {
            System.err.println("Error xifrant: " + ex);
        }
        return encryptedData;
    }

    public static byte[] decryptDataSinException(SecretKey sKey, byte[] encryptedData) {
        byte[] decryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, sKey);
            decryptedData = cipher.doFinal(encryptedData);
        } catch (Exception ex) {
        }
        return decryptedData;
    }

    public static KeyPair randomGenerate(int len) {
        KeyPair keys = null;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(len);
            keys = keyGen.genKeyPair();
        } catch (Exception ex) {
            System.err.println("Generador no disponible.");
        }
        return keys;
    }

    public static KeyStore loadKeyStore(String ksFile, String ksPwd) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        File f = new File(ksFile);
        if (f.isFile()) {
            FileInputStream in = new FileInputStream(f);
            ks.load(in, ksPwd.toCharArray());
        }
        return ks;
    }


    public static PublicKey getPublicKey(String fitxer) {
        PublicKey publicKey = null;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            FileInputStream fis = new FileInputStream(fitxer);
            X509Certificate certificate = (X509Certificate) cf.generateCertificate(fis);
            publicKey = certificate.getPublicKey();

            fis.close();
        } catch (Exception ex) {
            System.err.println("Error obtenint la PublicKey del certificat: " + ex);
        }
        return publicKey;
    }

    public static PublicKey getPublicKey(KeyStore ks, String alias, String pwMyKey) throws Exception {
        Certificate cert = (Certificate) ks.getCertificate(alias);
        PublicKey publicKey = cert.getPublicKey();
        return publicKey;
    }

    public static byte[] signData(byte[] data, PrivateKey priv) {
        byte[] signature = null;

        try {
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initSign(priv);
            signer.update(data);
            signature = signer.sign();
        } catch (Exception ex) {
            System.err.println("Error signant les dades: " + ex);
        }
        return signature;
    }

    public static PrivateKey getPrivateKeyFromKeystore() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        char[] password = "usuario".toCharArray();
        ks.load(new FileInputStream("/home/dam2a/mykeystore2.jks"), password);
        return (PrivateKey) ks.getKey("mykeypair", password);
    }

    public static boolean validateSignature(byte[] data, byte[] signature, PublicKey pub) {
        boolean isValid = false;
        try {
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initVerify(pub);
            signer.update(data);
            isValid = signer.verify(signature);
        } catch (Exception ex) {
            System.err.println("Error validant les dades: " + ex);
        }
        return isValid;
    }

    public static byte[][] encryptWrappedData(byte[] data, PublicKey pub) {
        // Se define un array de dos dimensiones que almacenará la información cifrada y la clave simétrica cifrada
        byte[][] encWrappedData = new byte[2][];
        try {
            // Se crea un objeto KeyGenerator para generar una clave simétrica AES de 128 bits
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128);
            SecretKey sKey = kgen.generateKey();
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, sKey);
            byte[] encMsg = cipher.doFinal(data);


            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.WRAP_MODE, pub);
            byte[] encKey = cipher.wrap(sKey);


            encWrappedData[0] = encMsg;
            encWrappedData[1] = encKey;
        } catch (Exception  ex) {
            System.err.println("Ha succeït un error xifrant: " + ex);
        }

        return encWrappedData;
    }

    public static byte[] decryptWrappedData(byte[][] encWrappedData, PrivateKey priv) {
        byte[] decData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.UNWRAP_MODE, priv);
            SecretKey sKey = (SecretKey) cipher.unwrap(encWrappedData[1], "AES", Cipher.SECRET_KEY);
            cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, sKey);
            decData = cipher.doFinal(encWrappedData[0]);
        } catch (Exception ex) {
            System.err.println("Ha succeït un error desxifrant: " + ex);
        }
        return decData;
    }
}