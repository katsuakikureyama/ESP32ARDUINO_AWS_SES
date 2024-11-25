#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <time.h>
#include "AWS_CERT_CA.h"
#include <mbedtls/md.h>



WiFiClientSecure client;


String toHexString(const unsigned char *data, uint16_t size) {
  String hexStr = "";
  for (uint16_t i = 0; i < size; i++) {
    String hex = String(data[i], HEX);
    if (hex.length() < 2) {
      hex = "0" + hex;  // 1桁の場合、前に0を追加して2桁にする
    }
    hexStr += hex;
  }
  return hexStr;
}


void generate_hmac_SHA256_hash(const byte *hmac_key, size_t key_len, const char *payload, byte *output_buffer) {
    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
    mbedtls_md_hmac_starts(&ctx, hmac_key, key_len);
    mbedtls_md_hmac_update(&ctx, (const unsigned char *)payload, strlen(payload));
    mbedtls_md_hmac_finish(&ctx, output_buffer);
    mbedtls_md_free(&ctx);
}
    
String calculateSignatureKey(const char *date, const char *region, const char *service, const char *secretKey, const char * stringToSign) {
    // `AWS4` + secretKey を使って kDate を生成
    String key = "AWS4" + String(secretKey);
    byte kDate[32];
    byte kRegion[32];
    byte kService[32];
    byte kSigning[32];
    byte signature[32];

    // kDate の生成
    generate_hmac_SHA256_hash((const byte *)key.c_str(), key.length(), date, kDate);
    // kRegion の生成
    generate_hmac_SHA256_hash(kDate, 32, region, kRegion);
    // kService の生成
    generate_hmac_SHA256_hash(kRegion, 32, service, kService);
    // kSigning の生成 ("aws4_request" を使う)
    generate_hmac_SHA256_hash(kService, 32, "aws4_request", kSigning);
  
    // 最終署名の生成 (stringToSign に対して)
    generate_hmac_SHA256_hash(kSigning, 32, stringToSign, signature);
  
    // 16進数表現に変換して返す
    return toHexString(signature, 32);
}


String calculatePayloadHash(String payload) {
  unsigned char hashResult[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);
  mbedtls_md_starts(&ctx);
  mbedtls_md_update(&ctx, (const unsigned char*)payload.c_str(), payload.length());
  mbedtls_md_finish(&ctx, hashResult);
  mbedtls_md_free(&ctx);
return toHexString(hashResult,32);
}

String urlEncode(String str) {
  String encoded = "";
  for (int i = 0; i < str.length(); i++) {
    char c = str.charAt(i);
    if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {  // AWSで許可される文字
      encoded += c;
    } else {
      encoded += '%';
      if (c < 0x10) encoded += '0';  // 1桁の場合、前に0を追加
      String hex = String(c, HEX);
      hex.toUpperCase();  // 大文字に変換
      encoded += hex;
    }
  }
  return encoded;
}
void sendSES(SimpleList &toAddresses, SimpleList &ccAddresses, SimpleList & bccAddresses, String subject, String body) {
  time_t now;
  struct tm timeinfo;
  if (!getLocalTime(&timeinfo)) {
    Serial.println("Failed to obtain time");
    return;
  }

  char date[9];
  strftime(date, sizeof(date), "%Y%m%d", &timeinfo);
  char dateTime[17];
  strftime(dateTime, sizeof(dateTime), "%Y%m%dT%H%M%SZ", &timeinfo);

  // Canonical URI and Query Stringの作成
  String canonicalUri = "/";
  String canonicalQueryString = "Action=SendEmail";

  // BCCアドレスを追加
  for (size_t i = 0; i < bccAddresses.size(); i++) {
    canonicalQueryString += "&Destination.BccAddresses.member." + String(i + 1) + "=" + urlEncode(bccAddresses[i]);
  }

  // CCアドレスを追加
  for (size_t i = 0; i < ccAddresses.size(); i++) {
    canonicalQueryString += "&Destination.CcAddresses.member." + String(i + 1) + "=" + urlEncode(ccAddresses[i]);
  }

  // TOアドレスを追加
  for (size_t i = 0; i < toAddresses.size(); i++) {
    canonicalQueryString += "&Destination.ToAddresses.member." + String(i + 1) + "=" + urlEncode(toAddresses[i]);
  }

  // メッセージ本文と件名
  canonicalQueryString += "&Message.Body.Text.Data=" + urlEncode(body);
  canonicalQueryString += "&Message.Subject.Data=" + urlEncode(subject);
  canonicalQueryString += "&Source=" + urlEncode(fromAddress.c_str());

  // Canonical Headers と Signed Headers の作成
  String canonicalHeaders = "host:" + awsHost + "\n" + "x-amz-date:" + dateTime;
  String signedHeaders = "host;x-amz-date";

  // Payload hash (空のペイロードを使う場合)
  String payloadHash = calculatePayloadHash("");

  // Canonical Requestの作成
  String canonicalRequest = "GET\n" + canonicalUri + "\n" + canonicalQueryString + "\n" + canonicalHeaders + "\n\n" + signedHeaders + "\n" + payloadHash;
  Serial.println("Canonical Request:\n" + canonicalRequest);

  // String to Signの作成
  String hashedCanonicalRequest;
  unsigned char hashResult[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);
  mbedtls_md_starts(&ctx);
  mbedtls_md_update(&ctx, (const unsigned char*)canonicalRequest.c_str(), canonicalRequest.length());
  mbedtls_md_finish(&ctx, hashResult);
  mbedtls_md_free(&ctx);
  
  hashedCanonicalRequest = toHexString(hashResult, 32);

  String stringToSign = "AWS4-HMAC-SHA256\n" + String(dateTime) + "\n" + String(date) + "/" + awsRegion + "/" + awsService + "/aws4_request\n" + hashedCanonicalRequest;
  Serial.println("String to Sign:\n" + stringToSign);
  
  String hexSignature = calculateSignatureKey(date, awsRegion.c_str(), awsService.c_str(), awsSecretKey.c_str(), stringToSign.c_str());
  Serial.println("Signature: " + hexSignature);
  
  // リクエストの送信
  if (client.connect(awsHost.c_str(), 443)) {
    client.println("GET /?" + canonicalQueryString + " HTTP/1.1");
    client.println("Authorization: AWS4-HMAC-SHA256 Credential=" + awsAccessKey + "/" + date + "/" + awsRegion + "/" + awsService + "/aws4_request, SignedHeaders=" + signedHeaders + ", Signature=" + hexSignature);
    client.println("Host: " + awsHost);
    client.println("X-Amz-Date: " + String(dateTime));
    client.println("Connection: close");
    client.println();

    Serial.println("GET /?" + canonicalQueryString + " HTTP/1.1");
    Serial.println("Authorization: AWS4-HMAC-SHA256 Credential=" + awsAccessKey + "/" + date + "/" + awsRegion + "/" + awsService + "/aws4_request, SignedHeaders=" + signedHeaders + ", Signature=" + hexSignature);
    Serial.println("Host: " + awsHost);
    Serial.println("X-Amz-Date: " + String(dateTime));
    Serial.println("Connection: close");
    Serial.println();

    while (client.connected()) {
      String line = client.readStringUntil('\n');
      Serial.println(line);
    }
  } else {
    Serial.println("Connection to AWS SES failed!");
  }
}

String replacePlaceholder(String text, const String& placeholder, const String& value) {
  text.replace(placeholder, value); // プレースホルダーを指定の値で置き換え
  return text; // 結果を返す
}
