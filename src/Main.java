import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        //Generem les claus
        System.out.println("Generar un parell de claus");
        KeyPair keyPair = Utilitats.randomGenerate(1024);

        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        //Missatge per teclat
        System.out.println("Escriu un missatge per xifrar-lo: ");
        String missatge = scanner.nextLine();

        byte[] xifrarDades = Utilitats.encryptData(missatge.getBytes(), publicKey);
        byte[] desxifrarDades = Utilitats.decryptData(xifrarDades, privateKey);
        String missatgeDesxifrat = new String(desxifrarDades);
        String missatgeXifrat = new String(xifrarDades);

        System.out.println("Missatge xifrat: "+ missatgeXifrat);
        System.out.println("Missatge desxifrat: "+missatgeDesxifrat);

        //loadKeystore
        System.out.println("\nLectura del KeyStore");

        KeyStore ks = Utilitats.loadKeyStore("/home/dam2a/mykeystore2.jks", "usuario");
        System.out.println("Tipus de keystore: "+ ks.getType());

        int size = ks.size();
        System.out.println("Mida del keystore: " + size);

        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.println("Àlies de la clau: " + alias);
        }

        String alias = "mykey";
        Certificate cert = ks.getCertificate(alias);
        System.out.println("Certificat de la clau " + alias + ": " + cert.toString());


        String aliasClaves = "mykeypair";
        Key key = ks.getKey(aliasClaves, "usuario".toCharArray());
        String algorithm = key.getAlgorithm();
        System.out.println("Algorisme de xifrat de la clau " + aliasClaves + ": " + algorithm);

        System.out.println("\nNova Clau Simètrica");

        SecretKey secretKey = Utilitats.keygenKeyGeneration(256);

        //Desem amb setEntry
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
        KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection("usuario".toCharArray());
        ks.setEntry("mykeypair", secretKeyEntry, entryPassword);

        ks.store(new FileOutputStream("/home/dam2a/mykeystore2.jks"), "usuario".toCharArray());

        System.out.println("\nRetorn de PublicKey");

        PublicKey publicKeyCer = Utilitats.getPublicKey("/home/dam2a/my_signed_certificate.cer");
        System.out.println("Valor: " + Arrays.toString(publicKeyCer.getEncoded()));
        System.out.println("Algorisme: " + publicKeyCer.getAlgorithm());
        System.out.println("Format: " + publicKeyCer.getFormat());

        System.out.println("\nLectura de clau Asimètrica");

        KeyStore ks4 = KeyStore.getInstance("PKCS12");
        char[] password = "usuario".toCharArray();
        ks4.load(new FileInputStream("/home/dam2a/mykeystore2.jks"), password);
        PublicKey publicKey4 = Utilitats.getPublicKey(ks4, "mykey", "usuario");
        System.out.println(publicKey4);

        System.out.println("\nRetorn de la Signatura");

        PrivateKey privateKey5 = Utilitats.getPrivateKeyFromKeystore();
        byte[] data = "Aquí trobem les dades a signar".getBytes();
        byte[] signature = Utilitats.signData(data, privateKey5);
        System.out.println("Amb la signatura: " + new String(signature));

        System.out.println("\nComprobació de la validesa");

        PublicKey publicKey6 = Utilitats.getPublicKey(ks4, "mykey", "usuario");
        byte[] signature6 =  Utilitats.signData(data, privateKey5);
        byte[] data6 = "Mostrem les dades signades".getBytes();
        boolean isValid = Utilitats.validateSignature(data6, signature6, publicKey6);

        if (isValid) {
            System.out.println("La firma es válida");
        } else {
            System.out.println("La firma NO es válida");
        }

        System.out.println("\nClau Embolcallada");

        KeyPair keyPair2 = Utilitats.randomGenerate(1024);
        PublicKey publicKey2 = keyPair2.getPublic();
        PrivateKey privateKey2 = keyPair2.getPrivate();

        String textToEncrypt = "Realitzat amb èxit";
        byte[] dataToEncrypt = textToEncrypt.getBytes();
        byte[][] encryptedData = Utilitats.encryptWrappedData(dataToEncrypt, publicKey2);
        byte[] decryptedData = Utilitats.decryptWrappedData(encryptedData, privateKey2);

        String decryptedText = new String(decryptedData);

        System.out.println("Text original: " + textToEncrypt);
        System.out.println("Text desxifrat: " + decryptedText);

    }
}