package ai.blip.wa.flows.media_uploader.service;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import ai.blip.wa.flows.media_uploader.model.MediaItem;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;

@Service
public class MediaDecryptionService {

    private final RestClient restClient;
    
    public MediaDecryptionService(RestClient.Builder restClientBuilder) {
        this.restClient = restClientBuilder.build();
        // Adiciona o Bouncy Castle como provedor de segurança
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Processa um item de mídia: baixa, valida e decripta.
     * @param mediaItem O objeto MediaItem recebido no payload.
     * @return Um array de bytes contendo a mídia decriptada.
     * @throws Exception Se qualquer passo da validação ou decriptação falhar.
     */
    public byte[] decryptMedia(MediaItem mediaItem) throws Exception {
        // 1. Baixar o arquivo da CDN
        byte[] cdnFile = downloadFile(mediaItem.getCdnUrl());

        // 2. Validar o hash do arquivo encriptado
        validateHash(cdnFile, mediaItem.getEncryptionMetadata().getEncryptedHash(), "SHA-256", "Encrypted file hash mismatch");

        // 3. Separar o ciphertext do hmac10
        byte[] ciphertext = Arrays.copyOfRange(cdnFile, 0, cdnFile.length - 10);
        byte[] hmac10 = Arrays.copyOfRange(cdnFile, cdnFile.length - 10, cdnFile.length);

        // 4. Validar o HMAC
        validateHmac(ciphertext, hmac10, mediaItem.getEncryptionMetadata().getIv(), mediaItem.getEncryptionMetadata().getHmacKey());

        // 5. Decriptar a mídia
        byte[] decryptedMedia = decryptAesCbc(ciphertext, mediaItem.getEncryptionMetadata().getEncryptionKey(), mediaItem.getEncryptionMetadata().getIv());

        // 6. Validar o hash do arquivo decriptado
        validateHash(decryptedMedia, mediaItem.getEncryptionMetadata().getPlaintextHash(), "SHA-256", "Plaintext file hash mismatch");

        System.out.println("✅ Mídia decriptada com sucesso: " + mediaItem.getFileName());
        return decryptedMedia;
    }

    private byte[] downloadFile(String url) {
        return restClient.get()
                .uri(url)
                .retrieve()
                .body(byte[].class);
    }

    private void validateHash(byte[] data, String expectedHashBase64, String algorithm, String errorMessage) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        byte[] actualHash = digest.digest(data);
        byte[] expectedHash = Base64.getDecoder().decode(expectedHashBase64);

        if (!MessageDigest.isEqual(actualHash, expectedHash)) {
            throw new SecurityException(errorMessage);
        }
    }

    private void validateHmac(byte[] ciphertext, byte[] hmac10, String ivBase64, String hmacKeyBase64) throws Exception {
        byte[] iv = Base64.getDecoder().decode(ivBase64);
        byte[] hmacKey = Base64.getDecoder().decode(hmacKeyBase64);

        // Concatena IV + Ciphertext
        byte[] dataToHmac = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, dataToHmac, 0, iv.length);
        System.arraycopy(ciphertext, 0, dataToHmac, iv.length, ciphertext.length);

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(hmacKey, "HmacSHA256"));
        byte[] fullHmac = mac.doFinal(dataToHmac);

        byte[] calculatedHmac10 = Arrays.copyOfRange(fullHmac, 0, 10);

        if (!MessageDigest.isEqual(calculatedHmac10, hmac10)) {
            throw new SecurityException("HMAC validation failed");
        }
    }

    private byte[] decryptAesCbc(byte[] ciphertext, String encryptionKeyBase64, String ivBase64) throws Exception {
        byte[] key = Base64.getDecoder().decode(encryptionKeyBase64);
        byte[] iv = Base64.getDecoder().decode(ivBase64);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(ciphertext);
    }
}