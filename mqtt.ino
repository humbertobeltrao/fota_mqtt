#include <WiFi.h>
#include <WebServer.h>

const char* ssid = "Humberto_ETECH_ULTRA";
const char* password = "astronauta3005";

WebServer server(80);

void handleWebhook() {
  if (server.hasArg("plain")) {
    String payload = server.arg("plain");
    Serial.println("Received Webhook Payload:");
    Serial.println(payload);

    // Parse payload to detect changes in version.json (use ArduinoJson library if needed)
  }
  server.send(200, "text/plain", "OK");
}

void setup() {
  Serial.begin(115200);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("Connected to WiFi");
  Serial.println(WiFi.localIP());

  server.on("/webhook", HTTP_POST, handleWebhook);
  server.begin();
}

void loop() {
  server.handleClient();
}
