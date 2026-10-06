/*
 * Copyright 2018-2026 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.swedenconnect.eid.sp.oidc;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * A local HTTP server used as test double for OP (and federation) endpoints.
 */
public class TestOpServer implements AutoCloseable {

  private final HttpServer server;

  private final Map<String, Function<HttpExchange, Response>> handlers = new ConcurrentHashMap<>();

  /**
   * A response.
   *
   * @param status the HTTP status
   * @param contentType the content type
   * @param body the body
   */
  public record Response(int status, String contentType, String body) {

    /**
     * A JSON response.
     *
     * @param json the JSON
     * @return a response
     */
    public static Response json(final JSONObject json) {
      return new Response(200, "application/json", json.toJSONString());
    }
  }

  /**
   * Starts a server on a random port.
   *
   * @throws IOException for errors
   */
  public TestOpServer() throws IOException {
    this.server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    this.server.createContext("/", this::handle);
    this.server.start();
  }

  /**
   * Gets the base URL.
   *
   * @return the base URL
   */
  public String getBaseUrl() {
    return "http://localhost:" + this.server.getAddress().getPort();
  }

  /**
   * Registers a handler for a path.
   *
   * @param path the path
   * @param handler the handler
   */
  public void on(final String path, final Function<HttpExchange, Response> handler) {
    this.handlers.put(path, handler);
  }

  /**
   * Removes a handler (the path then gives 404).
   *
   * @param path the path
   */
  public void remove(final String path) {
    this.handlers.remove(path);
  }

  private void handle(final HttpExchange exchange) throws IOException {
    final Function<HttpExchange, Response> handler = this.handlers.get(exchange.getRequestURI().getPath());
    final Response response = handler != null ? handler.apply(exchange) : new Response(404, "text/plain", "Not found");
    final byte[] body = response.body().getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().add("Content-Type", response.contentType());
    exchange.sendResponseHeaders(response.status(), body.length == 0 ? -1 : body.length);
    if (body.length > 0) {
      try (final OutputStream os = exchange.getResponseBody()) {
        os.write(body);
      }
    }
    exchange.close();
  }

  /**
   * Creates a minimal discovery document.
   *
   * @param issuer the issuer
   * @return a discovery document
   */
  public static JSONObject discoveryDocument(final String issuer) {
    final JSONObject doc = new JSONObject();
    doc.put("issuer", issuer);
    doc.put("authorization_endpoint", issuer + "/authorize");
    doc.put("token_endpoint", issuer + "/token");
    doc.put("userinfo_endpoint", issuer + "/userinfo");
    doc.put("jwks_uri", issuer + "/jwks");
    doc.put("response_types_supported", array(List.of("code")));
    doc.put("subject_types_supported", array(List.of("public")));
    doc.put("id_token_signing_alg_values_supported", array(List.of("RS256")));
    doc.put("scopes_supported", array(List.of("openid")));
    return doc;
  }

  /**
   * Creates a JSON array.
   *
   * @param values the values
   * @return a JSON array
   */
  public static JSONArray array(final List<?> values) {
    final JSONArray array = new JSONArray();
    array.addAll(values);
    return array;
  }

  @Override
  public void close() {
    this.server.stop(0);
  }

}
