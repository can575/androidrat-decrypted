import java.io.*;
import java.nio.file.*;
import java.util.zip.*;

public class ExtractMsuJson {
  static class RC4 {
    private final byte[] S = new byte[256];
    private int i = 0;
    private int j = 0;

    public RC4(byte[] key) {
      for (int i = 0; i < 256; i++) {
        S[i] = (byte) i;
      }
      int j = 0;
      for (int i = 0; i < 256; i++) {
        j = (j + (S[i] & 0xFF) + (key[i % key.length] & 0xFF)) & 0xFF;
        swap(i, j);
      }
    }

    private void swap(int i, int j) {
      byte temp = S[i];
      S[i] = S[j];
      S[j] = temp;
    }

    public byte[] decrypt(byte[] data) {
      byte[] output = new byte[data.length];
      for (int k = 0; k < data.length; k++) {
        i = (i + 1) & 0xFF;
        j = (j + (S[i] & 0xFF)) & 0xFF;
        swap(i, j);
        int t = ((S[i] & 0xFF) + (S[j] & 0xFF)) & 0xFF;
        output[k] = (byte) (data[k] ^ S[t]);
      }
      return output;
    }
  }

  public static void main(String[] args) {
    String encryptedFilePath = "Msu.json";
    String outputDir = "out";
    byte[] key = "NPZeIh" .getBytes();

    try {
      byte[] encryptedData = Files.readAllBytes(Paths.get(encryptedFilePath));
      RC4 rc4 = new RC4(key);
      byte[] decryptedData = rc4.decrypt(encryptedData);
      Files.createDirectories(Paths.get(outputDir));

      try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(decryptedData))) {
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
          Path entryPath = Paths.get(outputDir, entry.getName());
          if (entry.isDirectory()) {
            Files.createDirectories(entryPath);
          } else {
            Files.createDirectories(entryPath.getParent());
            try (OutputStream os = Files.newOutputStream(entryPath)) {
              byte[] buffer = new byte[1024];
              int len;
              while ((len = zis.read(buffer)) > 0) {
                os.write(buffer, 0, len);
              }
            }
          }
          zis.closeEntry();
        }
      }
      System.out.println("Successfully extracted " + encryptedFilePath + " contents to '" + outputDir + "' directory.");
    } catch (IOException e) {
      System.err.println("Error during extraction: " + e.getMessage());
      e.printStackTrace();
    }
  }
}