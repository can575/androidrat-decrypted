import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

public class DecryptJbetslwlt {
    private static final String KEY = "3qeJAqf1NLvlqWbRmxfnI1ghKgKmKXI7";
    private static final int STATE_SIZE = 256;

    private byte[] state = new byte[STATE_SIZE];
    private int i = 0;
    private int j = 0;

    public DecryptJbetslwlt() {
        initializeState();
        keySchedulingAlgorithm(KEY.getBytes());
    }

    private void initializeState() {
        for (int idx = 0; idx < STATE_SIZE; idx++) {
            state[idx] = (byte) idx;
        }
    }

    private void keySchedulingAlgorithm(byte[] key) {
        int keyLength = key.length;
        int j = 0;
        for (int i = 0; i < STATE_SIZE; i++) {
            j = (j + (state[i] & 0xFF) + (key[i % keyLength] & 0xFF)) & 0xFF;
            swap(i, j);
        }
    }

    private void swap(int i, int j) {
        byte temp = state[i];
        state[i] = state[j];
        state[j] = temp;
    }

    public byte[] decrypt(byte[] encryptedData) {
        byte[] decryptedData = new byte[encryptedData.length];
        for (int k = 0; k < encryptedData.length; k++) {
            i = (i + 1) & 0xFF;
            j = (j + (state[i] & 0xFF)) & 0xFF;
            swap(i, j);
            int t = ((state[i] & 0xFF) + (state[j] & 0xFF)) & 0xFF;
            decryptedData[k] = (byte) (encryptedData[k] ^ state[t]);
        }
        return decryptedData;
    }

    public static void main(String[] args) {
        try {
            FileInputStream fis = new FileInputStream("jbetslwlt");
            byte[] encryptedData = fis.readAllBytes();
            fis.close();

            DecryptJbetslwlt decryptor = new DecryptJbetslwlt();
            byte[] decryptedData = decryptor.decrypt(encryptedData);

            FileOutputStream fos = new FileOutputStream("jbetslwlt-decrypted.dex");
            fos.write(decryptedData);
            fos.close();

            System.out.println("Decryption successful. Decrypted file saved as 'jbetslwlt.dec'.");
        } catch (IOException e) {
            System.err.println("Error during decryption: " + e.getMessage());
            e.printStackTrace();
        }
    }
}