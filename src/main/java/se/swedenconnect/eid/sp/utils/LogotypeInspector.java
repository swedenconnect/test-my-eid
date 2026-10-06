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
package se.swedenconnect.eid.sp.utils;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Checks whether an SVG logotype is drawn mainly in white (or close to white), meaning that it is made for a dark
 * background and will be (more or less) invisible on the light background of the UI.
 * <p>
 * Logotypes given as URLs are downloaded in the background, and until the result is known, the logotype is reported as
 * not being light. Results are cached. Logotypes that are not SVG images are never reported as light.
 * </p>
 *
 * @author Martin Lindström
 */
public class LogotypeInspector implements DisposableBean {

  /** The logger. */
  private static final Logger log = LoggerFactory.getLogger(LogotypeInspector.class);

  /** Relative luminance from which a color is regarded as light. */
  private static final double LIGHT_LUMINANCE = 0.85;

  /** The maximum logotype size that we download. */
  private static final int MAX_SIZE = 1024 * 1024;

  /** Elements that paint shapes. */
  private static final Set<String> SHAPES = Set.of("path", "rect", "circle", "ellipse", "polygon", "polyline", "line",
      "text");

  /** Elements whose contents are not painted directly. */
  private static final Set<String> NOT_PAINTED = Set.of("defs", "mask", "clipPath", "symbol", "pattern", "marker",
      "metadata", "title", "desc", "style", "linearGradient", "radialGradient", "filter");

  /** Named colors that we understand (others are ignored). */
  private static final Map<String, int[]> NAMED_COLORS = Map.of(
      "white", new int[] { 255, 255, 255 },
      "black", new int[] { 0, 0, 0 },
      "snow", new int[] { 255, 250, 250 },
      "whitesmoke", new int[] { 245, 245, 245 },
      "ghostwhite", new int[] { 248, 248, 255 },
      "ivory", new int[] { 255, 255, 240 });

  /** Pattern for CSS class rules in a style element. */
  private static final Pattern CSS_RULE = Pattern.compile("([^{}]+)\\{([^}]*)}");

  /** Pattern for an rgb() color. */
  private static final Pattern RGB_COLOR =
      Pattern.compile("rgba?\\(\\s*(\\d+)\\s*,\\s*(\\d+)\\s*,\\s*(\\d+)\\s*(?:,[^)]*)?\\)");

  /** The time (in milliseconds) to keep a result. */
  private final long cacheTime;

  /** The HTTP client used to download logotypes. */
  private final HttpClient httpClient;

  /** Runs the downloads. */
  private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();

  /** The results, where the logotype URL is the key. */
  private final Map<String, Result> results = new ConcurrentHashMap<>();

  /**
   * Constructor.
   *
   * @param cacheTime the time (in seconds) to keep a result
   */
  public LogotypeInspector(final int cacheTime) {
    this.cacheTime = cacheTime * 1000L;
    this.httpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(5))
        .followRedirects(HttpClient.Redirect.NORMAL)
        .executor(this.executor)
        .build();
  }

  /**
   * Tells whether the logotype is an SVG image drawn mainly in white, and should be displayed on a dark background.
   *
   * @param logotype the logotype URL (may be a {@code data:} URL)
   * @return {@code true} if the logotype is known to be light, and {@code false} otherwise
   */
  public boolean isLightLogotype(final @Nullable String logotype) {
    if (logotype == null || logotype.isBlank()) {
      return false;
    }
    if (logotype.startsWith("data:")) {
      return this.results.computeIfAbsent(logotype, l -> new Result(this.inspectDataUrl(l), Long.MAX_VALUE)).light();
    }
    final Result result = this.results.get(logotype);
    if (result != null && result.expires() > System.currentTimeMillis()) {
      return result.light();
    }
    // Keep the old result (if any) until the new one is ready, and make sure that only one download is started ...
    final Result pending = new Result(result != null && result.light(), Long.MAX_VALUE);
    final boolean start = result == null
        ? this.results.putIfAbsent(logotype, pending) == null
        : this.results.replace(logotype, result, pending);
    if (start) {
      this.executor.execute(() -> this.results.put(logotype,
          new Result(this.inspectUrl(logotype), System.currentTimeMillis() + this.cacheTime)));
    }
    return pending.light();
  }

  /**
   * Downloads and inspects a logotype.
   *
   * @param url the logotype URL
   * @return whether the logotype is light
   */
  private boolean inspectUrl(final @NonNull String url) {
    try {
      final URI uri = URI.create(url);
      if (!"https".equalsIgnoreCase(uri.getScheme()) && !"http".equalsIgnoreCase(uri.getScheme())) {
        return false;
      }
      final HttpResponse<InputStream> response = this.httpClient.send(
          HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(10)).GET().build(),
          HttpResponse.BodyHandlers.ofInputStream());
      try (final InputStream body = response.body()) {
        if (response.statusCode() != 200) {
          log.debug("Could not download logotype '{}' - status {}", url, response.statusCode());
          return false;
        }
        final String contentType = response.headers().firstValue("Content-Type").orElse("");
        if (!contentType.contains("svg") && !uri.getPath().toLowerCase(Locale.ROOT).endsWith(".svg")) {
          return false;
        }
        final byte[] svg = body.readNBytes(MAX_SIZE + 1);
        if (svg.length > MAX_SIZE) {
          log.debug("Logotype '{}' is too large to inspect", url);
          return false;
        }
        return this.logResult(url, isLightSvg(svg));
      }
    }
    catch (final IOException | RuntimeException e) {
      log.debug("Could not download logotype '{}' - {}", url, e.getMessage());
      return false;
    }
    catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
      return false;
    }
  }

  /**
   * Inspects a logotype given as a {@code data:} URL.
   *
   * @param url the data URL
   * @return whether the logotype is light
   */
  private boolean inspectDataUrl(final @NonNull String url) {
    final int comma = url.indexOf(',');
    if (comma < 0) {
      return false;
    }
    final String header = url.substring(5, comma).toLowerCase(Locale.ROOT);
    if (!header.startsWith("image/svg+xml")) {
      return false;
    }
    try {
      final String data = url.substring(comma + 1);
      final byte[] svg = header.endsWith(";base64")
          ? Base64.getMimeDecoder().decode(data)
          : URLDecoder.decode(data, StandardCharsets.UTF_8).getBytes(StandardCharsets.UTF_8);
      return this.logResult("data:image/svg+xml", isLightSvg(svg));
    }
    catch (final IllegalArgumentException e) {
      log.debug("Invalid data URL for logotype - {}", e.getMessage());
      return false;
    }
  }

  /**
   * Logs the result of an inspection.
   *
   * @param logotype the logotype
   * @param light whether it is light
   * @return {@code light}
   */
  private boolean logResult(final @NonNull String logotype, final boolean light) {
    if (light) {
      log.debug("Logotype '{}' is drawn mainly in white and will be displayed on a dark background", logotype);
    }
    return light;
  }

  /**
   * Tells whether an SVG image is drawn mainly in white (or close to white). The fill colors of all painted shapes are
   * counted, and the image is light if more shapes are light than not. An image that has a non-light rectangle covering
   * it as its first shape (a background) is never light.
   *
   * @param svg the SVG document
   * @return {@code true} if the image is light
   */
  static boolean isLightSvg(final byte @NonNull [] svg) {
    final Document document;
    try {
      final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      factory.setNamespaceAware(true);
      factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
      factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
      factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
      factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
      factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
      factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
      factory.setExpandEntityReferences(false);
      final DocumentBuilder builder = factory.newDocumentBuilder();
      builder.setErrorHandler(null);
      document = builder.parse(new InputSource(new ByteArrayInputStream(svg)));
    }
    catch (final Exception e) {
      log.debug("Could not parse SVG logotype - {}", e.getMessage());
      return false;
    }
    final Element root = document.getDocumentElement();
    if (root == null || !"svg".equals(localName(root))) {
      return false;
    }
    final Counter counter = new Counter(cssClassFills(root), viewBox(root));
    counter.count(root, "#000000");
    return !counter.background && counter.light > counter.other;
  }

  /**
   * Collects the fill colors given for CSS classes in style elements.
   *
   * @param root the SVG root element
   * @return a map from class name to fill color
   */
  private static @NonNull Map<String, String> cssClassFills(final @NonNull Element root) {
    final Map<String, String> fills = new HashMap<>();
    final var styles = root.getElementsByTagNameNS("*", "style");
    for (int i = 0; i < styles.getLength(); i++) {
      final Matcher m = CSS_RULE.matcher(styles.item(i).getTextContent());
      while (m.find()) {
        final String fill = styleFill(m.group(2));
        if (fill == null) {
          continue;
        }
        for (final String selector : m.group(1).split(",")) {
          final String s = selector.trim();
          if (s.startsWith(".") && s.substring(1).matches("[\\w-]+")) {
            fills.put(s.substring(1), fill);
          }
        }
      }
    }
    return fills;
  }

  /**
   * Gets the width and height of the image from the {@code viewBox}, or {@code width} and {@code height}, attributes.
   *
   * @param root the SVG root element
   * @return the width and height, or {@code null} if unknown
   */
  private static double @Nullable [] viewBox(final @NonNull Element root) {
    try {
      final String[] parts = root.getAttribute("viewBox").trim().split("[\\s,]+");
      if (parts.length == 4) {
        return new double[] { Double.parseDouble(parts[2]), Double.parseDouble(parts[3]) };
      }
      return new double[] { length(root.getAttribute("width")), length(root.getAttribute("height")) };
    }
    catch (final NumberFormatException e) {
      return null;
    }
  }

  /**
   * Parses a length, ignoring the {@code px} unit.
   *
   * @param value the value
   * @return the length
   * @throws NumberFormatException for values that can not be parsed
   */
  private static double length(final @NonNull String value) {
    return Double.parseDouble(value.trim().replace("px", ""));
  }

  /**
   * Gets the fill color from a CSS declaration list.
   *
   * @param style the declarations
   * @return the fill color, or {@code null}
   */
  private static @Nullable String styleFill(final @Nullable String style) {
    if (style == null) {
      return null;
    }
    for (final String declaration : style.split(";")) {
      final int colon = declaration.indexOf(':');
      if (colon > 0 && "fill".equals(declaration.substring(0, colon).trim())) {
        return declaration.substring(colon + 1).replace("!important", "").trim();
      }
    }
    return null;
  }

  /**
   * Gets the local name of an element.
   *
   * @param element the element
   * @return the local name
   */
  private static @NonNull String localName(final @NonNull Element element) {
    return element.getLocalName() != null ? element.getLocalName() : element.getTagName();
  }

  /**
   * Parses a color into RGB components.
   *
   * @param color the color
   * @return the RGB components, or {@code null} if the color is not understood (or not a color)
   */
  static int @Nullable [] parseColor(final @NonNull String color) {
    final String c = color.trim().toLowerCase(Locale.ROOT);
    try {
      if (c.startsWith("#")) {
        final String hex = c.substring(1);
        if (hex.length() == 3 || hex.length() == 4) {
          return new int[] { Integer.parseInt(hex.substring(0, 1).repeat(2), 16),
              Integer.parseInt(hex.substring(1, 2).repeat(2), 16), Integer.parseInt(hex.substring(2, 3).repeat(2), 16) };
        }
        if (hex.length() == 6 || hex.length() == 8) {
          return new int[] { Integer.parseInt(hex.substring(0, 2), 16), Integer.parseInt(hex.substring(2, 4), 16),
              Integer.parseInt(hex.substring(4, 6), 16) };
        }
        return null;
      }
      final Matcher m = RGB_COLOR.matcher(c);
      if (m.matches()) {
        return new int[] { Integer.parseInt(m.group(1)), Integer.parseInt(m.group(2)), Integer.parseInt(m.group(3)) };
      }
    }
    catch (final NumberFormatException e) {
      return null;
    }
    return NAMED_COLORS.get(c);
  }

  /**
   * Tells whether a color is light, using its relative luminance.
   *
   * @param rgb the RGB components
   * @return {@code true} if the color is light
   */
  private static boolean isLight(final int @NonNull [] rgb) {
    final double luminance = 0.2126 * linear(rgb[0]) + 0.7152 * linear(rgb[1]) + 0.0722 * linear(rgb[2]);
    return luminance >= LIGHT_LUMINANCE;
  }

  /**
   * Converts an sRGB component to a linear value.
   *
   * @param component the component (0-255)
   * @return the linear value (0-1)
   */
  private static double linear(final int component) {
    final double c = Math.min(255, component) / 255.0;
    return c <= 0.04045 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
  }

  /** {@inheritDoc} */
  @Override
  public void destroy() {
    this.executor.shutdownNow();
  }

  /**
   * A cached result.
   *
   * @param light whether the logotype is light
   * @param expires when the result expires (millis since epoch)
   */
  private record Result(boolean light, long expires) {
  }

  /**
   * Counts light and other shapes in an SVG document.
   */
  private static class Counter {

    /** Fill colors for CSS classes. */
    private final Map<String, String> classFills;

    /** The width and height of the image (may be null). */
    private final double @Nullable [] size;

    /** The number of light shapes. */
    private int light;

    /** The number of other shapes. */
    private int other;

    /** Whether the first shape is a non-light background rectangle. */
    private boolean background;

    /**
     * Constructor.
     *
     * @param classFills fill colors for CSS classes
     * @param size the width and height of the image (may be null)
     */
    Counter(final @NonNull Map<String, String> classFills, final double @Nullable [] size) {
      this.classFills = classFills;
      this.size = size;
    }

    /**
     * Counts the shapes of an element and its children.
     *
     * @param element the element
     * @param inheritedFill the fill inherited from the parent
     */
    void count(final @NonNull Element element, final @NonNull String inheritedFill) {
      final String name = localName(element);
      if (NOT_PAINTED.contains(name) || "none".equals(element.getAttribute("display"))) {
        return;
      }
      final String fill = this.fill(element, inheritedFill);
      if (SHAPES.contains(name)) {
        final int[] rgb = parseColor(fill);
        if (rgb != null) {
          final boolean isLight = isLight(rgb);
          if (this.light == 0 && this.other == 0 && !isLight && "rect".equals(name) && this.covers(element)) {
            this.background = true;
          }
          if (isLight) {
            this.light++;
          }
          else {
            this.other++;
          }
        }
      }
      for (Node n = element.getFirstChild(); n != null; n = n.getNextSibling()) {
        if (n instanceof final Element child) {
          this.count(child, fill);
        }
      }
    }

    /**
     * Gets the fill of an element, where a style attribute is preferred over a CSS class, which is preferred over a
     * fill attribute.
     *
     * @param element the element
     * @param inheritedFill the fill inherited from the parent
     * @return the fill
     */
    private @NonNull String fill(final @NonNull Element element, final @NonNull String inheritedFill) {
      final String style = styleFill(element.getAttribute("style"));
      if (style != null) {
        return resolve(style, inheritedFill);
      }
      for (final String cls : element.getAttribute("class").trim().split("\\s+")) {
        final String classFill = this.classFills.get(cls);
        if (classFill != null) {
          return resolve(classFill, inheritedFill);
        }
      }
      return element.hasAttribute("fill") ? resolve(element.getAttribute("fill"), inheritedFill) : inheritedFill;
    }

    /**
     * Resolves {@code inherit}.
     *
     * @param fill the fill
     * @param inheritedFill the fill inherited from the parent
     * @return the fill
     */
    private static @NonNull String resolve(final @NonNull String fill, final @NonNull String inheritedFill) {
      return "inherit".equals(fill.trim()) ? inheritedFill : fill;
    }

    /**
     * Tells whether a rectangle covers (almost) the whole image.
     *
     * @param rect the rect element
     * @return {@code true} if it covers the image
     */
    private boolean covers(final @NonNull Element rect) {
      final String width = rect.getAttribute("width").trim();
      final String height = rect.getAttribute("height").trim();
      if ("100%".equals(width) && "100%".equals(height)) {
        return true;
      }
      if (this.size == null) {
        return false;
      }
      try {
        return length(width) >= this.size[0] * 0.9 && length(height) >= this.size[1] * 0.9;
      }
      catch (final NumberFormatException e) {
        return false;
      }
    }
  }

}
