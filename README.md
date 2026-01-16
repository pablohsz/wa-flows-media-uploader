# Documentação do Fluxo de Criptografia - Media Uploader

## 📋 Sumário
1. [Visão Geral](#visão-geral)
2. [Fluxo Completo de Execução](#fluxo-completo-de-execução)
3. [Etapa 1: Decriptação do Payload do Flow](#etapa-1-decriptação-do-payload-do-flow)
4. [Etapa 2: Decriptação das Mídias](#etapa-2-decriptação-das-mídias)
5. [Etapa 3: Encriptação da Resposta](#etapa-3-encriptação-da-resposta)
6. [Algoritmos Utilizados](#algoritmos-utilizados)
7. [Estrutura de Dados](#estrutura-de-dados)

---

## 🎯 Visão Geral

Este sistema processa requisições do **WhatsApp Flow** que contém mídias encriptadas. O fluxo envolve múltiplas camadas de segurança:

- **Camada 1**: Encriptação do payload do Flow (RSA + AES-GCM)
- **Camada 2**: Encriptação individual das mídias (AES-CBC + HMAC)
- **Camada 3**: Encriptação da resposta (AES-GCM)

---

## 🔄 Fluxo Completo de Execução

```
┌─────────────────────────────────────────────────────────────────┐
│  1. REQUISIÇÃO RECEBIDA (POST /media)                           │
│     - encrypted_flow_data (Base64)                              │
│     - encrypted_aes_key (Base64)                                │
│     - initial_vector (Base64)                                   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  2. DECRIPTAÇÃO DO PAYLOAD DO FLOW                              │
│     ├─ Decodifica Base64                                        │
│     ├─ Decripta chave AES com RSA-OAEP                         │
│     └─ Decripta payload com AES-GCM                            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  3. EXTRAÇÃO DOS DADOS                                          │
│     ├─ Parse JSON do payload decriptado                        │
│     ├─ Extrai objeto "data"                                    │
│     └─ Extrai lista de MediaItems (photo_picker, etc)          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  4. PARA CADA MÍDIA: DOWNLOAD E DECRIPTAÇÃO                     │
│     ├─ Download do arquivo da CDN                              │
│     ├─ Validação do hash do arquivo encriptado                 │
│     ├─ Separação: ciphertext + HMAC(10 bytes)                  │
│     ├─ Validação do HMAC                                       │
│     ├─ Decriptação AES-CBC                                     │
│     └─ Validação do hash do arquivo decriptado                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  5. SALVAR MÍDIA DECRIPTADA                                     │
│     └─ Arquivo salvo como: decrypted_[nome_original]           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  6. ENCRIPTAÇÃO DA RESPOSTA                                     │
│     ├─ Cria JSON de resposta                                   │
│     ├─ Inverte bits do IV (XOR 0xFF)                           │
│     └─ Encripta com AES-GCM usando chave AES original          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  7. RESPOSTA ENVIADA                                            │
│     └─ encrypted_flow_data (Base64)                            │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔓 Etapa 1: Decriptação do Payload do Flow

### 📍 Classe: `FlowEncryptionUtil`
### 📍 Método: `decryptRequestPayload()`

Esta é a **primeira camada de decriptação** e acontece no controller.

### **Passo 1.1: Decodificação Base64**

```java
byte[] encryptedFlowDataBytes = Base64.getDecoder().decode(request.getEncryptedFlowData());
byte[] encryptedAesKeyBytes = Base64.getDecoder().decode(request.getEncryptedAesKey());
byte[] initialVectorBytes = Base64.getDecoder().decode(request.getInitialVector());
```

**O que acontece:**
- Converte as strings Base64 recebidas em arrays de bytes
- Esses bytes serão usados nas operações criptográficas

---

### **Passo 1.2: Decriptação da Chave AES com RSA-OAEP**

```java
// Dentro de FlowEncryptionUtil.decryptRequestPayload()
final byte[] aes_key = decryptUsingRSA(privateKey, encrypted_aes_key);
```

**Algoritmo:** `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`

**Detalhes técnicos:**
- **RSA-OAEP**: RSA com Optimal Asymmetric Encryption Padding
- **Hash Function**: SHA-256
- **MGF**: MGF1 (Mask Generation Function) com SHA-256
- **Chave Privada**: Lida do arquivo `private_key.pem` (formato PKCS8)

**O que acontece:**
1. Carrega a chave privada RSA do arquivo PEM
2. Configura o cipher RSA-OAEP com os parâmetros corretos
3. Decripta a chave AES encriptada
4. Retorna a chave AES de 128 bits em claro

**Por que RSA?**
- A chave AES é pequena (128 bits) e precisa ser transmitida com segurança
- RSA é assimétrico: WhatsApp encripta com chave pública, servidor decripta com chave privada

---

### **Passo 1.3: Decriptação do Payload com AES-GCM**

```java
// Dentro de FlowEncryptionUtil.decryptUsingAES()
final GCMParameterSpec paramSpec = new GCMParameterSpec(AES_KEY_SIZE, iv);
final Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aes_key, "AES"), paramSpec);
final byte[] data = cipher.doFinal(encrypted_payload);
return new String(data, StandardCharsets.UTF_8);
```

**Algoritmo:** `AES/GCM/NoPadding`

**Parâmetros:**
- **Chave AES**: 128 bits (obtida no passo anterior)
- **IV (Vetor de Inicialização)**: 12-16 bytes
- **Modo**: GCM (Galois/Counter Mode)
- **Tag Size**: 128 bits (autenticação integrada)

**O que acontece:**
1. Configura o cipher AES-GCM com a chave e IV
2. Decripta o payload encriptado
3. O modo GCM valida automaticamente a autenticidade
4. Converte bytes para String UTF-8

**Por que AES-GCM?**
- **Rapidez**: GCM é muito eficiente
- **Autenticação integrada**: Garante integridade sem HMAC separado
- **Segurança**: Resistente a ataques de modificação

**Resultado:**
- JSON em texto claro contendo os dados do formulário e metadados das mídias

---

## 🔓 Etapa 2: Decriptação das Mídias

### 📍 Classe: `MediaDecryptionService`
### 📍 Método: `decryptMedia()`

Esta é a **segunda camada de decriptação** e processa cada arquivo de mídia individualmente.

### **Passo 2.1: Download do Arquivo da CDN**

```java
private byte[] downloadFile(String url) {
    return restClient.get()
            .uri(url)
            .retrieve()
            .body(byte[].class);
}
```

**O que acontece:**
- Faz requisição GET para a URL da CDN fornecida no `cdn_url`
- Baixa o arquivo encriptado completo como array de bytes
- O arquivo contém: `[ciphertext] + [HMAC de 10 bytes]`

**Nota de Segurança:**
- `RestClientConfig` está configurado para aceitar qualquer certificado SSL (apenas para desenvolvimento)
- Em produção, use validação SSL adequada

---

### **Passo 2.2: Validação do Hash do Arquivo Encriptado**

```java
validateHash(cdnFile, mediaItem.getEncryptionMetadata().getEncryptedHash(), 
             "SHA-256", "Encrypted file hash mismatch");
```

**Algoritmo:** SHA-256

**O que acontece:**
1. Calcula o hash SHA-256 do arquivo completo baixado
2. Compara com o `encrypted_hash` fornecido nos metadados
3. Se não coincidir, lança `SecurityException`

**Por quê?**
- Garante que o arquivo não foi corrompido ou modificado no trânsito
- Valida a integridade antes de prosseguir

---

### **Passo 2.3: Separação do Ciphertext e HMAC**

```java
byte[] ciphertext = Arrays.copyOfRange(cdnFile, 0, cdnFile.length - 10);
byte[] hmac10 = Arrays.copyOfRange(cdnFile, cdnFile.length - 10, cdnFile.length);
```

**Estrutura do arquivo:**
```
┌─────────────────────────────────┬──────────────┐
│      Ciphertext (N bytes)       │ HMAC (10 B)  │
└─────────────────────────────────┴──────────────┘
```

**O que acontece:**
- Separa os últimos 10 bytes (HMAC truncado)
- O restante é o ciphertext que será decriptado

---

### **Passo 2.4: Validação do HMAC**

```java
validateHmac(ciphertext, hmac10, 
             mediaItem.getEncryptionMetadata().getIv(), 
             mediaItem.getEncryptionMetadata().getHmacKey());
```

**Algoritmo:** HmacSHA256 (truncado para 10 bytes)

**Processo detalhado:**

```java
// 1. Decodifica IV e chave HMAC
byte[] iv = Base64.getDecoder().decode(ivBase64);
byte[] hmacKey = Base64.getDecoder().decode(hmacKeyBase64);

// 2. Concatena IV + Ciphertext
byte[] dataToHmac = new byte[iv.length + ciphertext.length];
System.arraycopy(iv, 0, dataToHmac, 0, iv.length);
System.arraycopy(ciphertext, 0, dataToHmac, iv.length, ciphertext.length);

// 3. Calcula HMAC-SHA256
Mac mac = Mac.getInstance("HmacSHA256");
mac.init(new SecretKeySpec(hmacKey, "HmacSHA256"));
byte[] fullHmac = mac.doFinal(dataToHmac);

// 4. Trunca para 10 bytes
byte[] calculatedHmac10 = Arrays.copyOfRange(fullHmac, 0, 10);

// 5. Compara com o HMAC recebido
if (!MessageDigest.isEqual(calculatedHmac10, hmac10)) {
    throw new SecurityException("HMAC validation failed");
}
```

**O que é HMAC?**
- **Hash-based Message Authentication Code**
- Verifica se os dados foram modificados
- Usa uma chave secreta (não pode ser forjado sem a chave)

**Por que apenas 10 bytes?**
- Reduz overhead mantendo segurança adequada
- WhatsApp Flow usa esse padrão

**Por que incluir o IV?**
- Garante que IV não foi trocado
- Previne ataques de replay com IV diferente

---

### **Passo 2.5: Decriptação AES-CBC**

```java
byte[] decryptedMedia = decryptAesCbc(ciphertext, 
                                      mediaItem.getEncryptionMetadata().getEncryptionKey(), 
                                      mediaItem.getEncryptionMetadata().getIv());
```

**Algoritmo:** `AES/CBC/PKCS7Padding`

**Processo detalhado:**

```java
// 1. Decodifica chave e IV
byte[] key = Base64.getDecoder().decode(encryptionKeyBase64);
byte[] iv = Base64.getDecoder().decode(ivBase64);

// 2. Configura cipher AES-CBC com Bouncy Castle
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
cipher.init(Cipher.DECRYPT_MODE, 
            new SecretKeySpec(key, "AES"), 
            new IvParameterSpec(iv));

// 3. Decripta
return cipher.doFinal(ciphertext);
```

**Parâmetros:**
- **Modo**: CBC (Cipher Block Chaining)
- **Padding**: PKCS7 (adiciona bytes de preenchimento)
- **Provider**: Bouncy Castle (para PKCS7Padding)
- **Tamanho da chave**: 256 bits (tipicamente)

**O que é CBC?**
- Cada bloco é XOR com o bloco anterior antes de encriptar
- O IV é usado como "bloco anterior" do primeiro bloco
- Garante que padrões repetidos no plaintext não apareçam no ciphertext

**Por que Bouncy Castle?**
- JDK padrão usa PKCS5Padding
- PKCS7 é mais flexível e usado pelo WhatsApp

---

### **Passo 2.6: Validação do Hash do Arquivo Decriptado**

```java
validateHash(decryptedMedia, 
             mediaItem.getEncryptionMetadata().getPlaintextHash(), 
             "SHA-256", 
             "Plaintext file hash mismatch");
```

**Algoritmo:** SHA-256

**O que acontece:**
1. Calcula SHA-256 do arquivo decriptado
2. Compara com `plaintext_hash` dos metadados
3. Lança exceção se não coincidir

**Por quê?**
- Validação final de integridade
- Garante que a decriptação foi bem-sucedida
- Confirma que é o arquivo original correto

---

### **Passo 2.7: Salvar Arquivo**

```java
try (FileOutputStream fos = new FileOutputStream("decrypted_" + item.getFileName())) {
    fos.write(decryptedMedia);
}
```

**O que acontece:**
- Salva o arquivo decriptado no sistema de arquivos
- Nome do arquivo: `decrypted_[nome_original]`
- Arquivo agora está em formato original, pronto para uso

---

## 🔐 Etapa 3: Encriptação da Resposta

### 📍 Classe: `FlowEncryptionUtil`
### 📍 Método: `encryptAndEncodeResponse()`

Esta é a **terceira camada** - encriptação da resposta para o WhatsApp Flow.

### **Passo 3.1: Criar JSON de Resposta**

```java
JSONObject responseJson = new JSONObject();
JSONObject responseData = new JSONObject();
responseData.put("status", "active");
responseJson.put("data", responseData);
String clearResponse = responseJson.toJSONString();
```

**Resultado (exemplo):**
```json
{
  "data": {
    "status": "active"
  }
}
```

**O que acontece:**
- Cria estrutura JSON com os dados de resposta
- Converte para string JSON

---

### **Passo 3.2: Inversão do Vetor de Inicialização**

```java
FlowEncryptionUtil.flipIv(initialVectorBytes)
```

**Implementação:**
```java
public static byte[] flipIv(final byte[] iv) {
    final byte[] result = new byte[iv.length];
    for (int i = 0; i < iv.length; i++) {
        result[i] = (byte) (iv[i] ^ 0xFF); // XOR com 0xFF inverte todos os bits
    }
    return result;
}
```

**O que acontece:**
- Inverte todos os bits do IV original
- Exemplo: `0b10101100` → `0b01010011`

**Por quê?**
- Protocolo do WhatsApp Flow exige IV diferente para resposta
- Usar o mesmo IV para encriptar seria inseguro
- XOR com 0xFF é uma forma simples e determinística de gerar novo IV

---

### **Passo 3.3: Encriptação AES-GCM**

```java
String encryptedResponse = FlowEncryptionUtil.encryptAndEncodeResponse(
    clearResponse, 
    decryptionInfo.clearAesKey,  // Mesma chave AES usada na decriptação
    flippedIv                     // IV invertido
);
```

**Algoritmo:** `AES/GCM/NoPadding`

**Processo detalhado:**

```java
// 1. Configura parâmetros GCM
final GCMParameterSpec paramSpec = new GCMParameterSpec(128, iv);

// 2. Inicializa cipher
final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
cipher.init(Cipher.ENCRYPT_MODE, 
            new SecretKeySpec(aes_key, "AES"), 
            paramSpec);

// 3. Encripta
final byte[] encryptedData = cipher.doFinal(clearResponse.getBytes(StandardCharsets.UTF_8));

// 4. Codifica em Base64
return Base64.getEncoder().encodeToString(encryptedData);
```

**O que acontece:**
1. Converte JSON string para bytes UTF-8
2. Encripta com AES-GCM usando:
   - Mesma chave AES da requisição
   - IV invertido (diferente da requisição)
3. GCM adiciona automaticamente tag de autenticação
4. Codifica resultado em Base64 para transmissão

**Por que reusar a chave AES?**
- Evita necessidade de trocar nova chave
- Protocolo do WhatsApp Flow permite isso
- Segurança mantida pelo IV diferente

---

### **Passo 3.4: Retornar Resposta**

```java
return ResponseEntity.ok(encryptedResponse);
```

**Formato da resposta:**
```json
{
  "encrypted_flow_data": "[Base64 da resposta encriptada]"
}
```

**O que acontece:**
- WhatsApp recebe a resposta encriptada
- Decripta usando a mesma chave AES e IV invertido
- Processa os dados da resposta

---

## 🔐 Algoritmos Utilizados

### **Resumo dos Algoritmos**

| Etapa | Algoritmo | Propósito | Tamanho da Chave |
|-------|-----------|-----------|------------------|
| Decriptação da chave AES | RSA/ECB/OAEPWithSHA-256AndMGF1Padding | Troca segura de chave | 2048+ bits |
| Decriptação do payload Flow | AES/GCM/NoPadding | Decriptação + autenticação | 128 bits |
| Validação de hash | SHA-256 | Integridade de arquivos | N/A |
| Validação de autenticidade | HmacSHA256 (truncado) | Autenticação de mensagem | Variável |
| Decriptação de mídia | AES/CBC/PKCS7Padding | Decriptação de conteúdo | 256 bits |
| Encriptação de resposta | AES/GCM/NoPadding | Encriptação + autenticação | 128 bits |

---

## 📦 Estrutura de Dados

### **1. FlowRequest (Requisição inicial)**

```json
{
  "encrypted_flow_data": "Base64...",
  "encrypted_aes_key": "Base64...",
  "initial_vector": "Base64..."
}
```

### **2. Payload Decriptado**

```json
{
  "version": "3.0",
  "screen": "PHOTO_PICKER",
  "data": {
    "photo_picker": [
      {
        "media_id": "123456",
        "cdn_url": "https://cdn.example.com/file.enc",
        "file_name": "photo.jpg",
        "encryption_metadata": {
          "encrypted_hash": "Base64...",
          "iv": "Base64...",
          "encryption_key": "Base64...",
          "hmac_key": "Base64...",
          "plaintext_hash": "Base64..."
        }
      }
    ]
  }
}
```

### **3. EncryptionMetadata (Metadados de cada mídia)**

| Campo | Descrição | Uso |
|-------|-----------|-----|
| `encrypted_hash` | SHA-256 do arquivo encriptado | Validar integridade do download |
| `iv` | Vetor de inicialização | Usado na decriptação AES-CBC |
| `encryption_key` | Chave AES | Decriptação do arquivo |
| `hmac_key` | Chave HMAC | Validação de autenticidade |
| `plaintext_hash` | SHA-256 do arquivo original | Validar decriptação correta |

### **4. Resposta Encriptada**

```json
{
  "encrypted_flow_data": "Base64..."
}
```

**Após decriptação pelo WhatsApp:**
```json
{
  "data": {
    "status": "active"
  }
}
```

---

## 🔒 Conceitos de Segurança

### **Defesa em Profundidade**

O sistema usa múltiplas camadas de segurança:

1. **RSA-OAEP**: Troca segura de chaves
2. **AES-GCM**: Encriptação autenticada do payload
3. **SHA-256**: Validação de integridade
4. **HMAC**: Autenticação de mensagem
5. **AES-CBC**: Encriptação do conteúdo da mídia

### **Por que tantas camadas?**

- **RSA**: Segurança na troca inicial de chaves
- **AES**: Rapidez na encriptação de dados grandes
- **GCM**: Autenticação integrada (mais eficiente)
- **CBC + HMAC**: Compatibilidade com padrão WhatsApp para mídias
- **Hashes**: Detecção de corrupção/modificação

### **Considerações Importantes**

1. **IVs únicos**: Nunca reutilize IV com mesma chave
2. **Validação de HMAC**: Sempre antes de decriptar
3. **Validação de hash**: Detecta adulteração/corrupção
4. **Chaves separadas**: Encriptação e HMAC usam chaves diferentes
5. **Ordem de operações**: Hash → HMAC → Decriptação → Hash

---

## 🚀 Fluxo Resumido (TL;DR)

```
RECEBER → Decriptar payload (RSA+AES-GCM) → Extrair mídias
    ↓
Para cada mídia:
    Download → Hash Check → Separar HMAC → Validar HMAC
    ↓
    Decriptar (AES-CBC) → Hash Check → Salvar
    ↓
RESPONDER → Criar JSON → Inverter IV → Encriptar (AES-GCM) → Enviar
```

---

## 📚 Referências

- [WhatsApp Business Platform - Flows](https://developers.facebook.com/docs/whatsapp/flows)
- [AES-GCM Specification (NIST SP 800-38D)](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [RSA-OAEP (RFC 8017)](https://datatracker.ietf.org/doc/html/rfc8017)
- [HMAC Specification (RFC 2104)](https://datatracker.ietf.org/doc/html/rfc2104)
- [Bouncy Castle Provider](https://www.bouncycastle.org/)

---

## 📝 Notas de Implementação

### **Arquivo de Chave Privada**

O sistema busca `private_key.pem` em ordem de prioridade:

1. Variável de ambiente: `ENDPOINT_PRIVATE_KEY_FILE_PATH`
2. Arquivo na raiz do projeto: `private_key.pem`

Formato esperado: PKCS8, não encriptado

```
-----BEGIN PRIVATE KEY-----
[Base64 content]
-----END PRIVATE KEY-----
```

### **Dependências**

- **Bouncy Castle**: Para PKCS7Padding
- **Apache HttpClient 5**: Para SSL customizado
- **Jackson**: Para parsing JSON
- **JSON Simple**: Para construção de resposta

### **Configuração SSL**

⚠️ **ATENÇÃO**: `RestClientConfig` aceita todos os certificados SSL. Use apenas em desenvolvimento!

Para produção, remova o bypass de SSL ou configure truststore apropriado.

---

## ✅ Checklist de Validação

Para cada requisição, o sistema valida:

- [ ] Hash do arquivo encriptado baixado
- [ ] HMAC do ciphertext
- [ ] Hash do arquivo decriptado
- [ ] Formato do payload JSON
- [ ] Presença de todos os campos obrigatórios

Qualquer falha resulta em exceção e resposta de erro.

---

**Versão:** 1.0  
