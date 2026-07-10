#pragma once
/**
 * WebDashboard
 * ------------
 * A minimal, read-only HTTP status page showing recent alerts from
 * AlertLogger. Deliberately contains no <form> elements, no credential
 * fields, and no redirect/portal tricks — this is a monitoring display,
 * not a captive portal.
 */

#include <ESP8266WebServer.h>

class WebDashboard {
public:
    // Starts the HTTP server on port 80.
    void begin();

    // Call from loop() to service incoming HTTP requests.
    void handleClient();

private:
    ESP8266WebServer _server{80};

    void handleRoot();
    void handleAlertsJson();
    String renderPage() const;
};
