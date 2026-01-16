package ai.blip.wa.flows.media_uploader.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class EncryptionMetadata {

    @JsonProperty("encrypted_hash")
    private String encryptedHash;

    @JsonProperty("iv")
    private String iv;

    @JsonProperty("encryption_key")
    private String encryptionKey;

    @JsonProperty("hmac_key")
    private String hmacKey;

    @JsonProperty("plaintext_hash")
    private String plaintextHash;

    // Getters e Setters
    public String getEncryptedHash() { return encryptedHash; }
    public void setEncryptedHash(String encryptedHash) { this.encryptedHash = encryptedHash; }
    public String getIv() { return iv; }
    public void setIv(String iv) { this.iv = iv; }
    public String getEncryptionKey() { return encryptionKey; }
    public void setEncryptionKey(String encryptionKey) { this.encryptionKey = encryptionKey; }
    public String getHmacKey() { return hmacKey; }
    public void setHmacKey(String hmacKey) { this.hmacKey = hmacKey; }
    public String getPlaintextHash() { return plaintextHash; }
    public void setPlaintextHash(String plaintextHash) { this.plaintextHash = plaintextHash; }
}