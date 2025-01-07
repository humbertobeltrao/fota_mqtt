#include <SPIFFS.h>
#include <WiFi.h>
#include <PubSubClient.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <Update.h>
#include <mbedtls/aes.h>
#include <SD.h>
#include <mbedtls/platform.h>
#include <string.h>
#include <Arduino.h>
#include <mbedtls/md.h>
#include "cert.h"
#include <time.h>
#include <TimeLib.h>


// MQTT and WiFi configuration
const char* mqtt_server = "test.mosquitto.org"; // MQTT server
const char* ssid = "";
const char* password = "";
String updateUrl;
String updateVersionCheck;

// NTP server and timezone
const char* ntpServer = "pool.ntp.org";
const long gmtOffset_sec = -3 * 3600;      // Adjust for your timezone (e.g., -5 * 3600 for GMT-5)
const int daylightOffset_sec = 3600; 

// SD card setup
#define SD_CS_PIN 5

WiFiClientSecure espClient;
PubSubClient client(espClient); // MQTT client

// AES decryption setup
unsigned char aes_key[16]; // 128-bit AES key (16 bytes)
unsigned char aes_iv[16];  // 128-bit AES IV (16 bytes)
unsigned char hmac[16]; // 128-bit AES key (16 bytes)
String aes_key_for_mac = "1234567890123456";

String encrypted_url_hex = "";
String downloadUrl = "";
bool has_key = false;
bool has_iv = false;
bool has_encrypted_url = false;
bool has_pad = false;
File file;
size_t padded_length = 0; // Initialize padded_length to 0
unsigned char padded_input[128] = {0}; // Initialize with zeros to avoid undefined behavior
unsigned char encrypted[128] = {0};     // Initialize with zeros
unsigned char decrypted[128] = {0};     // Initialize with zeros
size_t decrypted_url_len = 0; // Initialize decrypted_url_len to 0

bool has_hmac = false;
String received_hmac = "";
String computed_hmac_hex = "";
unsigned char output[32]; // SHA-256 generates a 256-bit HMAC (32 bytes)
time_t utcReceived;
time_t currentEspTime;
bool has_url = false;
String timestamp = "";

// Function to perform AES decryption
void aes_decrypt(unsigned char *key, unsigned char *iv, unsigned char *input, unsigned char *output, size_t input_len) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    // Set up AES context for decryption
    mbedtls_aes_setkey_dec(&aes, key, 128);

    // Perform AES decryption in CBC mode
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, input_len, iv, input, output);
    
    mbedtls_aes_free(&aes);
}

void hex_to_bytes(const char* hex, unsigned char* bytes, size_t* length) {
    size_t hex_len = strlen(hex);
    *length = hex_len / 2; // Each byte is represented by two hex characters
    for (size_t i = 0; i < *length; i++) {
        sscanf(hex + (2 * i), "%2hhx", &bytes[i]);
    }
}

void calculateHMAC(const char* key_hex, const char* message_hex, char* output_str) {
    unsigned char key[64], message[256];
    size_t key_len, message_len;

    // Convert hex strings to raw bytes
    hex_to_bytes(key_hex, key, &key_len);
    hex_to_bytes(message_hex, message, &message_len);

    // Initialize HMAC
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, md_info, 1);
    mbedtls_md_hmac_starts(&ctx, key, key_len);
    mbedtls_md_hmac_update(&ctx, message, message_len);
    mbedtls_md_hmac_finish(&ctx, output);
    mbedtls_md_free(&ctx);

    // Print HMAC as a hex string
    for (int i = 0; i < 32; i++) {
        sprintf(&output_str[i * 2], "%02x", output[i]); // Append each byte as hex
    }
    printf("\n");
}


time_t convertStringToUTC(const String& timestampStr) {
  int year, month, day, hour, minute, second;

  // Parse the input string (format: "2024-12-09T19:42:24")
  int result = sscanf(timestampStr.c_str(), "%d-%d-%d %d:%d:%d", 
                       &year, &month, &day, &hour, &minute, &second);

  if (result != 6) {
    Serial.println("Failed to parse timestamp string.");
    return 0;  // Return 0 if parsing fails
  }

  // Create tmElements_t structure for conversion
  tmElements_t tm;
  tm.Year = year - 1970;  // time_t starts at 1970
  tm.Month = month;
  tm.Day = day;
  tm.Hour = hour;
  tm.Minute = minute;
  tm.Second = second;

  // Convert to time_t (seconds since January 1, 1970)
  time_t timestamp = makeTime(tm);
  return timestamp;
}


// Function to convert hex string to byte array
void hexStringToByteArray(String hex, byte* byteArray, int length) {
    for (int i = 0; i < length * 2; i += 2) {
        byteArray[i / 2] = strtol(hex.substring(i, i + 2).c_str(), NULL, 16);
    }
}

// Function to decode the encrypted URL
bool decryptAndDownloadFirmware() {
   
    hexStringToByteArray(encrypted_url_hex, encrypted, encrypted_url_hex.length() / 2);
    Serial.println(encrypted_url_hex);
    Serial.println("Encrypted Data:");
    for (size_t i = 0; i < encrypted_url_hex.length() / 2; i++) {
        Serial.printf("%02X ", encrypted[i]);
    }
    Serial.println();
    
    Serial.print("AES Key: ");
    for (int i = 0; i < sizeof(aes_key); i++) {
        Serial.printf("%02X ", aes_key[i]);
    }
    Serial.println();

    Serial.print("AES IV: ");
    for (int i = 0; i < sizeof(aes_iv); i++) {
        Serial.printf("%02X ", aes_iv[i]);
    }

    // Decrypt the URL
    aes_decrypt(aes_key, aes_iv, encrypted, decrypted, padded_length);
    
    
    // Unpad the decrypted URL (removes PKCS#7 padding)c
    decrypted_url_len = unpad_input(decrypted, padded_length, decrypted);
    decrypted[decrypted_url_len] = '\0';  // Null-terminate the string
    
    Serial.println("Decrypted:");
    //Serial.println((char *)decrypted);
    // Download the firmware
    delay(3000);
    return downloadFirmware((char *)decrypted);
}

// Function to unpad input data according to PKCS#7
size_t unpad_input(const unsigned char *input, size_t input_len, unsigned char *output) {
    // Get the padding length from the last byte
    size_t pad_len = input[input_len - 1];
    // Copy the data up to the padding length
    memcpy(output, input, input_len - pad_len);
    return input_len - pad_len;
}

void callback(char* topic, byte* payload, unsigned int length) {
    String message;
    for (int i = 0; i < length; i++) {
        message += (char)payload[i];
    }

    if (String(topic) == "esp32/key") {
        aes_key_for_mac = message;
        //Serial.print("KEY: ");
        //Serial.println(aes_key_for_mac);
        message.getBytes(aes_key, 16 + 1);
        //message.getBytes(aes_key_for_mac, 16 + 1);
        has_key = true;
        //Serial.println(message);
    } else if (String(topic) == "esp32/iv") {
        message.getBytes(aes_iv, 16 + 1);
        has_iv = true;
        //Serial.println(message);
    } else if (String(topic) == "esp32/pad") {
          //hexStringToByteArray(message, aes_iv, 16);
        //Serial.println(message);
        padded_length = (size_t)message.toInt();
        has_pad = true;
    } else if (String(topic) == "esp32/update") {
        encrypted_url_hex = message;
        Serial.print("Content: ");
        Serial.println(encrypted_url_hex.c_str());
        has_encrypted_url = true;
    } else if (String(topic) == "esp32/mac") {
        received_hmac = message;
        has_hmac = true;
    } else if (String(topic) == "timestamp") {
       timestamp = message;
       has_url = true;
    }

    // Proceed if all data is received
    if (has_key && has_iv && has_encrypted_url && has_pad && has_hmac && has_url) {
        Serial.print("Timestamp Received: ");
        Serial.println(timestamp.c_str());
        utcReceived = convertStringToUTC(timestamp);
        char hmac_output[65];
        calculateHMAC("313233", encrypted_url_hex.c_str(), hmac_output);
        // Convert computed HMAC to hex string
        
        for (int i = 0; i < 32; i++) {
            computed_hmac_hex += String(output[i], HEX);
        }
        Serial.print("Computed HMAC: ");
        Serial.println(computed_hmac_hex);
        Serial.print("Received HMAC: ");
        Serial.println(received_hmac);
        // Compare the received HMAC with the computed HMAC
        if (strcmp(hmac_output, received_hmac.c_str()) == 0) {
            Serial.println("HMAC verified successfully!");
            if (decryptAndDownloadFirmware()) {
              Serial.println("Done!");
                //flashESP32();
            } else {
                Serial.println("Decryption failed. Check key, IV, and encrypted data.");
            }
        } else {
            Serial.println("HMAC verification failed. Data integrity compromised.");
        }

        resetFlags();
    }
}

void reconnect() {
    while (!client.connected()) {
        Serial.println("Attempting MQTT connection...");
        if (client.connect("ESP32_clientID")) {
            Serial.println("connected");
            client.subscribe("esp32/update");
            client.subscribe("esp32/iv");
            client.subscribe("esp32/key");
            client.subscribe("esp32/pad");
            client.subscribe("esp32/mac");
            client.subscribe("timestamp");
        } else {
            Serial.print("failed, rc=");
            Serial.print(client.state());
            Serial.println(" try again in 5 seconds");
            delay(5000);
        }
    }
}

// Get the current UTC time as `time_t`
time_t getCurrentUTCTime() {
  struct tm timeinfo;
  if (!getLocalTime(&timeinfo)) {
    Serial.println("Failed to obtain time");
    return 0;
  }
  return mktime(&timeinfo); // Convert tm structure to time_t (epoch seconds)
}


void setup() {
    Serial.begin(115200);
     if (!SPIFFS.begin(true)) {
        Serial.println("SPIFFS Mount Failed");
        return;
    }
    WiFi.begin(ssid, password);
    configTime(gmtOffset_sec, daylightOffset_sec, ntpServer);
    struct tm timeinfo;
    while (!getLocalTime(&timeinfo)) {
      Serial.println("Failed to obtain time");
      delay(1000);
    }

      // Initialize SD card
    if (!SD.begin(SD_CS_PIN)) {
      Serial.println("SD card initialization failed!");
      return;
    }
    espClient.setCACert(mosquittoCertificate);
    client.setServer(mqtt_server, 8883); // Secure MQTT port (8883)
    client.setCallback(callback);
    connectmqtt();
}

void loop() {
    if (!client.connected()) {
        reconnect();
    }
    client.loop();
}

String getTimestamp() {
    time_t now = time(nullptr); // Get current time
    struct tm* timeinfo = localtime(&now); // Convert to local time

    char buffer[20];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo); // Format as "YYYY-MM-DD HH:mm:SS"
    
    return String(buffer); // Return timestamp as String
}

void connectmqtt() {
    if (client.connect("ESP32_clientID")) {
        Serial.println("connected to MQTT");
        client.subscribe("esp32/update");
        client.subscribe("esp32/iv");
        client.subscribe("esp32/key");
        client.subscribe("esp32/pad");
        client.subscribe("esp32/mac");
        client.subscribe("timestamp");
    } else {
        reconnect();
    }
}

bool downloadFirmware(const char* url) {
    Serial.println(url);
    WiFiClientSecure * client = new WiFiClientSecure;

    if (client) {
        client->setCACert(rootCACertificate);  // Set root CA certificate for HTTPS

        HTTPClient https;
        if (https.begin( * client, url)) {
            Serial.print("[HTTPS] GET...\n");
            delay(100);
            int httpCode = https.GET();
            if (httpCode == HTTP_CODE_MOVED_PERMANENTLY || httpCode == HTTP_CODE_FOUND || httpCode == HTTP_CODE_SEE_OTHER) {
              String redirectURL = https.getLocation();  // Get the new URL from the Location header
              Serial.print("Redirecting to: ");
              Serial.println(redirectURL);
              https.end();  // Close the initial connection
          
              // Begin a new connection with the redirect URL
              https.begin(* client, redirectURL);
              httpCode = https.GET();  // Make the new request
            }
            delay(100);
            if (httpCode == HTTP_CODE_OK) {
              
                Serial.println("Downloading file...");

                //file = SPIFFS.open("/update.bin", FILE_WRITE);
                file = SD.open("/update.bin", FILE_WRITE);

                WiFiClient* stream = https.getStreamPtr();
                
                int totalDownloaded = 0;
                unsigned long startTime = millis();
                while (https.connected() && (https.getSize() > 0 || https.getSize() == -1)) {
                  static uint8_t buffer[16384];
                    size_t size = stream->available();
                    if (size) {
                        int bytesRead = stream->readBytes(buffer, ((size > sizeof(buffer)) ? sizeof(buffer) : size));
                        file.write(buffer, bytesRead);
                        totalDownloaded += bytesRead;
                        Serial.print("Downloaded: ");
                        Serial.print(totalDownloaded);
                        Serial.println(" bytes");
                    }
                     // Break the loop when all data has been downloaded
                    if (https.getSize() != -1 && totalDownloaded >= https.getSize()) {
                        break;
                    }
                    
                }

                file.close();
                Serial.print("Download completed in ");
                Serial.print(millis() - startTime);
                Serial.println(" ms");
                Serial.println(getCurrentUTCTime());
                currentEspTime = convertStringToUTC(getTimestamp());
                long diff = currentEspTime - utcReceived;
                Serial.print("Total time: ");
                Serial.print(diff);
                Serial.println(" s");
                //writtenToSD = true;
                //Serial.println("Start to transfer firmware via UDS...");
                //sendUDSExtendedDiagnosticSessionRequest();
                //delay(1000);
            } else {
                Serial.print("Error Occurred During Download: ");
                Serial.println(httpCode);
                
            }
            https.end();
        }
        delete client;
        return true;
    }
    return false;
}

void flashESP32() {
    File updateBin = SPIFFS.open("/update.bin", FILE_READ);
    if (!updateBin) return;
    if (!Update.begin(updateBin.size())) {
        updateBin.close();
        return;
    }
    size_t written = Update.writeStream(updateBin);
    if (Update.end() && Update.isFinished()) {
        Serial.println("Update successfully completed. Rebooting.");
        ESP.restart();
    }
    updateBin.close();
}

void resetFlags() {
    has_key = false;
    has_iv = false;
    has_encrypted_url = false;
    memset(aes_key, 0, sizeof(aes_key));  // Clears the aes_key array
    memset(aes_iv, 0, sizeof(aes_iv));    // Clears the aes_iv array
    encrypted_url_hex = "";
}
