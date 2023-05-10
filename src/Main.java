import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
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

        KeyStore ks = Utilitats.loadKeyStore("/home/dam2a/mykeystore.jks", "usuari");
        System.out.println("Tipo de keystore: "+ ks.getType());

        int size = ks.size();
        System.out.println("Tamaño del keystore: " + size);

        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.println("Alias de la clave: " + alias);
        }

        String alias = "mykeypair";
        Certificate cert = ks.getCertificate(alias);
        System.out.println("Certificado de la clave " + alias + ": " + cert.toString());


        String aliasClaves = "mykeypair";
        Key key = ks.getKey(aliasClaves, "usuario".toCharArray());
        String algorithm = key.getAlgorithm();
        System.out.println("Algoritmo de cifrado de la clave " + aliasClaves + ": " + algorithm);
    }
}