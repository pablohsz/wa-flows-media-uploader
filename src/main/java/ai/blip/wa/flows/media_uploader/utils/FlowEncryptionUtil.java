package ai.blip.wa.flows.media_uploader.utils;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class FlowEncryptionUtil {

    public static class DecryptionInfo {
        public final String clearPayload;
        public final byte[] clearAesKey;

        public DecryptionInfo(String clearPayload, byte[] clearAesKey) {
            this.clearPayload = clearPayload;
            this.clearAesKey = clearAesKey;
        }
    }

    private static final int AES_KEY_SIZE = 128;
    private static final String KEY_GENERATOR_ALGORITHM = "AES";
    private static final String AES_CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    private static final String RSA_ENCRYPT_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String RSA_MD_NAME = "SHA-256";
    private static final String RSA_MGF = "MGF1";

    /**
     * Decripta o payload recebido do WhatsApp Flow
     * 
     * @param encrypted_flow_data Dados encriptados em Base64
     * @param encrypted_aes_key Chave AES encriptada em Base64
     * @param initial_vector Vetor de inicialização em Base64
     * @return DecryptionInfo contendo o payload decriptado e a chave AES
     * @throws Exception Se houver erro na decriptação
     */
    public static DecryptionInfo decryptRequestPayload(
            byte[] encrypted_flow_data, 
            byte[] encrypted_aes_key, 
            byte[] initial_vector
    ) throws Exception {
        // Passamos null para que a lógica de busca da chave seja ativada
        final RSAPrivateKey privateKey = readPrivateKeyFromPkcs8UnencryptedPem(null);
        final byte[] aes_key = decryptUsingRSA(privateKey, encrypted_aes_key);
        return new DecryptionInfo(
            decryptUsingAES(encrypted_flow_data, aes_key, initial_vector), 
            aes_key
        );
    }

    /**
     * Encripta a resposta para enviar ao WhatsApp Flow
     * 
     * @param clearResponse Resposta em texto claro (JSON string)
     * @param aes_key Chave AES obtida na decriptação
     * @param iv Vetor de inicialização (deve ser invertido com flipIv)
     * @return String Base64 da resposta encriptada
     * @throws GeneralSecurityException Se houver erro na encriptação
     */
    public static String encryptAndEncodeResponse(
            final String clearResponse, 
            final byte[] aes_key, 
            final byte[] iv
    ) throws GeneralSecurityException {
        final GCMParameterSpec paramSpec = new GCMParameterSpec(AES_KEY_SIZE, iv);
        final Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aes_key, KEY_GENERATOR_ALGORITHM), paramSpec);
        final byte[] encryptedData = cipher.doFinal(clearResponse.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    /**
     * Inverte os bits do vetor de inicialização (necessário para encriptação da resposta)
     * 
     * @param iv Vetor de inicialização original
     * @return Vetor de inicialização invertido
     */
    public static byte[] flipIv(final byte[] iv) {
        final byte[] result = new byte[iv.length];
        for (int i = 0; i < iv.length; i++) {
            result[i] = (byte) (iv[i] ^ 0xFF);
        }
        return result;
    }

    /**
     * Decripta usando AES-GCM
     */
    private static String decryptUsingAES(
            final byte[] encrypted_payload, 
            final byte[] aes_key, 
            final byte[] iv
    ) throws GeneralSecurityException {
        final GCMParameterSpec paramSpec = new GCMParameterSpec(AES_KEY_SIZE, iv);
        final Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aes_key, KEY_GENERATOR_ALGORITHM), paramSpec);
        final byte[] data = cipher.doFinal(encrypted_payload);
        return new String(data, StandardCharsets.UTF_8);
    }

    /**
     * Decripta usando RSA-OAEP
     */
    private static byte[] decryptUsingRSA(
            final RSAPrivateKey privateKey, 
            final byte[] payload
    ) throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(RSA_ENCRYPT_ALGORITHM);
        cipher.init(
            Cipher.DECRYPT_MODE, 
            privateKey, 
            new OAEPParameterSpec(RSA_MD_NAME, RSA_MGF, MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT)
        );
        return cipher.doFinal(payload);
    }

    /**
     * Lê a chave privada do arquivo PEM
     * 
     * @param filePath Caminho do arquivo .pem
     * @return Chave privada RSA
     * @throws Exception Se o arquivo não existir ou formato inválido
     */
    private static RSAPrivateKey readPrivateKeyFromPkcs8UnencryptedPem(String filePath) throws Exception {
        // Ordem de prioridade:
        // 1. Parâmetro passado
        // 2. Variável de ambiente ENDPOINT_PRIVATE_KEY_FILE_PATH
        // 3. Arquivo na raiz do projeto: private_key.pem
        
        if (filePath == null || filePath.isEmpty()) {
            filePath = System.getenv("ENDPOINT_PRIVATE_KEY_FILE_PATH");
        }
        
        if (filePath == null || filePath.isEmpty()) {
            // Fallback: usa o caminho padrão na raiz do projeto
            filePath = "private_key.pem";
        }

        File keyFile = new File(filePath);
        
        if (!keyFile.exists()) {
            throw new IllegalStateException(
                "Private key file not found at: " + keyFile.getAbsolutePath() + "\n" +
                "Please:\n" +
                "1. Place private_key.pem in the project root, OR\n" +
                "2. Set ENDPOINT_PRIVATE_KEY_FILE_PATH environment variable with the full path"
            );
        }

        final String prefix = "-----BEGIN PRIVATE KEY-----";
        final String suffix = "-----END PRIVATE KEY-----";
        
        String key = new String(Files.readAllBytes(keyFile.toPath()), StandardCharsets.UTF_8);
        
        if (!key.contains(prefix)) {
            throw new IllegalStateException("Expecting unencrypted private key in PKCS8 format starting with " + prefix);
        }
        
        String privateKeyPEM = key.replace(prefix, "")
                                  .replaceAll("[\\r\\n]", "")
                                  .replace(suffix, "");
        
        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }
}