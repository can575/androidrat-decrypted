package uwu.narumi.deobfuscator.core.other.impl.other;

import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import uwu.narumi.deobfuscator.api.transformer.Transformer;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

public class RC4StringTransformer extends Transformer {

    @Override
    protected void transform() throws Exception {
        AtomicInteger decryptedCount = new AtomicInteger(0);
        
        scopedClasses().forEach(classWrapper -> {
            classWrapper.methods().forEach(methodNode -> {
                Arrays.stream(methodNode.instructions.toArray()).forEach(node -> {
                    if (node instanceof LdcInsnNode ldc &&
                            ldc.cst instanceof String hexString &&
                        node.getNext() instanceof MethodInsnNode next && 
                        next.getOpcode() == INVOKESTATIC) {

                        if (next.desc.equals("(Ljava/lang/String;)Ljava/lang/String;")) {

                            if (isValidHexString(hexString)) {
                                try {
                                    String decrypted = decryptHex(hexString);
                                    ldc.cst = decrypted;
                                    methodNode.instructions.remove(next);
                                    
                                    decryptedCount.incrementAndGet();
                                    this.markChange();
                                    
                                    LOGGER.debug("Decrypted RC4 string: {} -> {}", hexString, decrypted);
                                } catch (Exception e) {
                                    LOGGER.warn("Failed to decrypt RC4 string: {}", hexString, e);
                                }
                            }
                        }
                    }
                });
            });
        });
        
        LOGGER.info("Decrypted {} RC4 strings in {} classes", decryptedCount.get(), scopedClasses().size());
    }
    
    /**
     * Validates if a string is a valid hex string
     */
    private boolean isValidHexString(String hex) {
        if (hex == null || hex.length() % 2 != 0) {
            return false;
        }
        
        return hex.matches("^[0-9a-fA-F]+$");
    }
    
    /**
     * Decrypts a hex-encoded string using RC4 with the fixed key
     */
    private String decryptHex(String hexInput) {
        byte[] key = "5p6MX5YkeOHVYU6rf0oJjoUrEvXvML".getBytes(StandardCharsets.UTF_8);
        RC4Cipher rc4 = new RC4Cipher(key);
        byte[] data = hexStringToByteArray(hexInput);
        return rc4.process(data);
    }
    
    /**
     * Converts hex string to byte array
     */
    private byte[] hexStringToByteArray(String hex) {
        int len = hex.length();
        byte[] buf = new byte[len / 2];
        for (int pos = 0; pos < len; pos += 2) {
            buf[pos / 2] = (byte) ((Character.digit(hex.charAt(pos), 16) << 4)
                    + Character.digit(hex.charAt(pos + 1), 16));
        }
        return buf;
    }
    
    /**
     * Simple RC4 cipher implementation
     */
    private static class RC4Cipher {
        private final int[] sBox;
        private int i;
        private int j;
        
        public RC4Cipher(byte[] key) {
            this.sBox = initializeState(key);
        }
        
        private int[] initializeState(byte[] key) {
            int[] state = new int[256];
            for (int k = 0; k < 256; k++) {
                state[k] = k;
            }
            int j = 0;
            for (int k = 0; k < 256; k++) {
                j = (j + state[k] + (key[k % key.length] & 0xFF)) & 0xFF;
                swap(state, k, j);
            }
            return state;
        }
        
        private void swap(int[] array, int x, int y) {
            int tmp = array[x];
            array[x] = array[y];
            array[y] = tmp;
        }
        
        public String process(byte[] data) {
            byte[] output = new byte[data.length];
            for (int idx = 0; idx < data.length; idx++) {
                i = (i + 1) & 0xFF;
                j = (j + sBox[i]) & 0xFF;
                swap(sBox, i, j);
                int t = (sBox[i] + sBox[j]) & 0xFF;
                output[idx] = (byte) (data[idx] ^ sBox[t]);
            }
            return new String(output, StandardCharsets.UTF_8);
        }
    }
}