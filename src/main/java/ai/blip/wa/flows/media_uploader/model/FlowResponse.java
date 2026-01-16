package ai.blip.wa.flows.media_uploader.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class FlowResponse {

    @JsonProperty("encrypted_flow_data")
    private String encryptedFlowData;

    public FlowResponse(String encryptedFlowData) {
        this.encryptedFlowData = encryptedFlowData;
    }

    // Getter e Setter
    public String getEncryptedFlowData() {
        return encryptedFlowData;
    }

    public void setEncryptedFlowData(String encryptedFlowData) {
        this.encryptedFlowData = encryptedFlowData;
    }
}