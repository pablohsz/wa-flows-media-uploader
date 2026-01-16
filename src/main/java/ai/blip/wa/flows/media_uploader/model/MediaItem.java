package ai.blip.wa.flows.media_uploader.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class MediaItem {

    @JsonProperty("media_id")
    private String mediaId;

    @JsonProperty("cdn_url")
    private String cdnUrl;

    @JsonProperty("file_name")
    private String fileName;

    @JsonProperty("encryption_metadata")
    private EncryptionMetadata encryptionMetadata;

    // Getters e Setters
    public String getMediaId() { return mediaId; }
    public void setMediaId(String mediaId) { this.mediaId = mediaId; }
    public String getCdnUrl() { return cdnUrl; }
    public void setCdnUrl(String cdnUrl) { this.cdnUrl = cdnUrl; }
    public String getFileName() { return fileName; }
    public void setFileName(String fileName) { this.fileName = fileName; }
    public EncryptionMetadata getEncryptionMetadata() { return encryptionMetadata; }
    public void setEncryptionMetadata(EncryptionMetadata encryptionMetadata) { this.encryptionMetadata = encryptionMetadata; }
}