package ai.blip.wa.flows.media_uploader.controller;

import ai.blip.wa.flows.media_uploader.model.FlowRequest;
import ai.blip.wa.flows.media_uploader.model.MediaItem;
import ai.blip.wa.flows.media_uploader.service.MediaDecryptionService;
import ai.blip.wa.flows.media_uploader.utils.FlowEncryptionUtil;
import ai.blip.wa.flows.media_uploader.utils.FlowEncryptionUtil.DecryptionInfo;
import lombok.var;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.simple.JSONObject;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.FileOutputStream;
import java.util.Base64;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/media")
public class MediaController {

    private final MediaDecryptionService mediaDecryptionService;
    private final ObjectMapper objectMapper;

    public MediaController(MediaDecryptionService mediaDecryptionService, ObjectMapper objectMapper) {
        this.mediaDecryptionService = mediaDecryptionService;
        this.objectMapper = objectMapper;
    }

    @GetMapping("/get")
    public ResponseEntity<Object> findAll() {
        String response = new StringBuilder("Media items retrieved successfully").toString();
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    @PostMapping
    public ResponseEntity<Object> uploadMedia(@RequestBody FlowRequest request) {
        try {
            // 1. Decriptar o payload principal do Flow
            byte[] encryptedFlowDataBytes = Base64.getDecoder().decode(request.getEncryptedFlowData());
            byte[] encryptedAesKeyBytes = Base64.getDecoder().decode(request.getEncryptedAesKey());
            byte[] initialVectorBytes = Base64.getDecoder().decode(request.getInitialVector());

            DecryptionInfo decryptionInfo = FlowEncryptionUtil.decryptRequestPayload(
                    encryptedFlowDataBytes, encryptedAesKeyBytes, initialVectorBytes);

            System.out.println("✅ Payload do Flow Decriptado: " + decryptionInfo.clearPayload);

            // 2. Mapear o payload decriptado para um Map
            Map<String, Object> decryptedPayload = objectMapper.readValue(decryptionInfo.clearPayload,
                    new TypeReference<>() {
                    });

            // 3. Extrair o objeto "data" que contém os dados do formulário
            Map<String, Object> data = (Map<String, Object>) decryptedPayload.get("data");

            // 3.1 Extrair a propriedade "flow_token" que contém o token necessário no
            // objeto de retorno pro Flow
            String flowToken = (String) decryptedPayload.get("flow_token");

            // 3.2 Extrair a propriedade "action" para checar se é uma Health Check Request
            String action = (String) decryptedPayload.get("action");

            // 3.3 Declar o objeto JSON de resposta
            JSONObject responseData = new JSONObject();
            JSONObject responseJson = new JSONObject();

            // 4. Checar se é uma Health Check Request
            if ("ping".equals(action)) {
                responseData.put("status", "active");
                responseJson.put("data", responseData);
                var clearResponse = responseJson.toJSONString();

                var encryptedResponse = FlowEncryptionUtil.encryptAndEncodeResponse(
                        clearResponse, decryptionInfo.clearAesKey, FlowEncryptionUtil.flipIv(initialVectorBytes));
                // 4.1 Retorna a resposta esperada pelo Health Check
                return ResponseEntity.ok(encryptedResponse);
            }

            // 5. Processar cada tipo de mídia (ex: photo_picker)
            if (data != null && data.containsKey("photo_picker")) {
                List<MediaItem> mediaItems = objectMapper.convertValue(
                        data.get("photo_picker"),
                        new TypeReference<List<MediaItem>>() {
                        });

                for (MediaItem item : mediaItems) {
                    // 6. Decriptar a mídia
                    byte[] decryptedMedia = mediaDecryptionService.decryptMedia(item);

                    // 7. Salvar o arquivo (exemplo)
                    try (FileOutputStream fos = new FileOutputStream("decrypted_" + item.getFileName())) {
                        fos.write(decryptedMedia);
                    }
                    System.out.println("💾 Mídia salva como: decrypted_" + item.getFileName());
                }
            }
            // Adicione outros `if` para "document_picker", "video_picker", etc.

            // 8. Criar e encriptar a resposta para o Flow
            responseData.put("flow_token", flowToken);
            responseData.put("msgTitle", "Sucesso no Upload de Mídia");
            responseData.put("msgResponse", "O upload da mídia foi concluído com sucesso.");
            responseData.put("mediaUrl", "https://example.com/media/decrypted_media.jpg");
            responseJson.put("data", responseData);
            responseJson.put("screen", "SECOND");
            String clearResponse = responseJson.toJSONString();

            String encryptedResponse = FlowEncryptionUtil.encryptAndEncodeResponse(
                    clearResponse, decryptionInfo.clearAesKey, FlowEncryptionUtil.flipIv(initialVectorBytes));

            return ResponseEntity.ok(encryptedResponse);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error processing request: " + e.getMessage());
        }
    }
}