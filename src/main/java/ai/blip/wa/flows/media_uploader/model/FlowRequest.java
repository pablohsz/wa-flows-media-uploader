package ai.blip.wa.flows.media_uploader.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class FlowRequest {

    @JsonProperty("encrypted_flow_data")
    private String encryptedFlowData;

    @JsonProperty("encrypted_aes_key")
    private String encryptedAesKey;

    @JsonProperty("initial_vector")
    private String initialVector;

    // Getters e Setters
    public String getEncryptedFlowData() {
        return encryptedFlowData;
    }

    public void setEncryptedFlowData(String encryptedFlowData) {
        this.encryptedFlowData = encryptedFlowData;
    }

    public String getEncryptedAesKey() {
        return encryptedAesKey;
    }

    public void setEncryptedAesKey(String encryptedAesKey) {
        this.encryptedAesKey = encryptedAesKey;
    }

    public String getInitialVector() {
        return initialVector;
    }

    public void setInitialVector(String initialVector) {
        this.initialVector = initialVector;
    }
}