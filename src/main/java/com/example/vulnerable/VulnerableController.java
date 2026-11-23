package com.example.vulnerable;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.HtmlUtils;
import org.w3c.dom.Document;
import org.yaml.snakeyaml.Yaml;

import java.security.spec.InvalidKeySpecException;
import javax.crypto.spec.PBEKeySpec;
import java.security.*;
import javax.crypto.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.*;
import java.security.MessageDigest;
import java.sql.*;
import java.util.*;

/**
 * Intentionally Vulnerable REST Controller
 * DO NOT USE IN PRODUCTION - FOR SECURITY TESTING ONLY
 */
@RestController
@RequestMapping("/api")
public class VulnerableController {

    // In-memory user store (simulating database)
    private static final List<Map<String, Object>> users = new ArrayList<>();

    static {
        Map<String, Object> admin = new HashMap<>();
        admin.put("id", 1);
        admin.put("username", "admin");
        admin.put("password", "hashed_password");
        admin.put("email", "admin@example.com");
        admin.put("role", "admin");
        users.add(admin);

        Map<String, Object> user = new HashMap<>();
        user.put("id", 2);
        user.put("username", "user");
        user.put("password", "hashed_password");
        user.put("email", "user@example.com");
        user.put("role", "user");
        users.add(user);
    }

    @GetMapping("/")
    public String index() {
        return """
                <html>
                <head><title>Vulnerable Java App</title></head>
                <body>
                    <h1>Intentionally Vulnerable Spring Boot Application</h1>
                    <p>This application contains numerous security vulnerabilities for testing purposes.</p>
                    <h2>Available Endpoints:</h2>
                    <ul>
                        <li>POST /api/login - SQL Injection</li>
                        <li>GET /api/exec?cmd=ls - Command Injection</li>
                        <li>GET /api/files?filename=test.txt - Path Traversal</li>
                        <li>POST /api/upload - Unrestricted File Upload</li>
                        <li>GET /api/search?query=test - XSS</li>
                        <li>GET /api/proxy?url=http://example.com - SSRF</li>
                        <li>POST /api/evaluate - RCE via Script Engine</li>
                        <li>POST /api/deserialize - Insecure Deserialization</li>
                        <li>DELETE /api/admin/users/{id} - Missing Authentication</li>
                        <li>GET /api/users/{id} - IDOR</li>
                        <li>POST /api/parse-xml - XXE Injection</li>
                        <li>POST /api/parse-yaml - YAML Deserialization</li>
                        <li>POST /api/register - Mass Assignment</li>
                        <li>GET /api/debug - Sensitive Data Exposure</li>
                        <li>GET /redirect?url= - Open Redirect</li>
                    </ul>
                </body>
                </html>
                """;
    }

    // VULNERABILITY: SQL Injection (CWE-89)
    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody Map<String, String> credentials) {
        String username = credentials.get("username");
        String password = credentials.get("password");

        // Vulnerable: Direct string concatenation simulating SQL injection
        String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        System.out.println("Query: " + query);  // This would be vulnerable in real SQL

        Map<String, Object> response = new HashMap<>();
        for (Map<String, Object> user : users) {
            if (user.get("username").equals(username)) {
                // VULNERABILITY: Weak JWT with predictable secret (CWE-327)
                String token = "fake_jwt_token_" + username + "_" + System.currentTimeMillis();
                response.put("success", true);
                response.put("token", token);
                response.put("user", user);
                return response;
            }
        }

        response.put("success", false);
        response.put("message", "Invalid credentials");
        return response;
    }

    // VULNERABILITY: Command Injection (CWE-78)
    private static final Map<String, List<String>> ALLOWED_COMMANDS = Map.of(
        "date", List.of("date"),
        "whoami", List.of("whoami"),
        "uptime", List.of("uptime")
    );

    @GetMapping("/exec")
    public Map<String, Object> executeCommand(@RequestParam String cmd) {
        Map<String, Object> response = new HashMap<>();
        List<String> command = ALLOWED_COMMANDS.get(cmd);

        if (command == null) {
            response.put("success", false);
            response.put("error", "Command not allowed");
            return response;
        }

        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            Process process = pb.start();
            StringBuilder output = new StringBuilder();

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }
            process.waitFor();

            response.put("success", true);
            response.put("output", output.toString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            response.put("error", "Command execution was interrupted");
        } catch (IOException e) {
            response.put("error", e.getMessage());
        }
        return response;
    }

    @GetMapping("/files")
    public Map<String, Object> getFile(@RequestParam String filename) {
        Map<String, Object> response = new HashMap<>();
        try {
            Path baseDir = Paths.get(System.getProperty("user.dir"), "uploads")
                    .toAbsolutePath()
                    .normalize();
            Path targetPath = baseDir.resolve(filename).normalize();
            if (!targetPath.startsWith(baseDir)) {
                response.put("error", "Invalid file path");
                return response;
            }
            String content = new String(Files.readAllBytes(targetPath));
            response.put("content", content);
        } catch (IOException e) {
            response.put("error", "File not found");
        }
        return response;
    }

    @PostMapping("/upload")
    public Map<String, Object> uploadFile(@RequestParam("file") String fileContent,
                                          @RequestParam("filename") String filename) {
        Map<String, Object> response = new HashMap<>();
        try {
            Path baseDir = Paths.get(System.getProperty("user.dir"), "uploads")
                    .toAbsolutePath()
                    .normalize();
            Path targetPath = baseDir.resolve(filename).normalize();

            if (!targetPath.startsWith(baseDir)) {
                response.put("success", false);
                response.put("error", "Invalid file path");
                return response;
            }

            Files.write(targetPath, fileContent.getBytes());

            response.put("success", true);
            response.put("filename", filename);
            response.put("path", targetPath.toString());
        } catch (IOException e) {
            response.put("error", e.getMessage());
        }
        return response;
    }

    @GetMapping("/search")
    public String search(@RequestParam String query) {
        String safeQuery = HtmlUtils.htmlEscape(query);
        return "<h1>Search Results for: " + safeQuery + "</h1>";
    }

    // VULNERABILITY: Server-Side Request Forgery (SSRF) (CWE-918)
    @GetMapping("/proxy")
    public Map<String, Object> proxy(@RequestParam String url) {
        Map<String, Object> response = new HashMap<>();
        try {
            // Vulnerable: No URL validation, allows internal network access
            URL targetUrl = new URL(url);
            HttpURLConnection connection = (HttpURLConnection) targetUrl.openConnection();
            connection.setRequestMethod("GET");

            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line);
            }
            reader.close();

            response.put("data", content.toString());
            response.put("status", connection.getResponseCode());
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        return response;
    }

    // VULNERABILITY: Remote Code Execution via Script Engine (CWE-94)
    @PostMapping("/evaluate")
    public Map<String, Object> evaluate(@RequestBody Map<String, String> request) {
        Map<String, Object> response = new HashMap<>();
        try {
            String expression = request.get("expression");
            // Vulnerable: Evaluating user input (similar to eval in other languages)
            // In Java, this would typically use ScriptEngine, but we'll simulate
            response.put("warning", "Would execute: " + expression);
            response.put("result", "Execution simulated (dangerous in real implementation)");
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        return response;
    }

@PostMapping("/deserialize")
    public Map<String, Object> deserialize(@RequestBody byte[] data) {
        Map<String, Object> response = new HashMap<>();
        try {
            ObjectMapper mapper = new ObjectMapper();
            Object obj = mapper.readValue(data, Map.class);
            response.put("result", obj.toString());
        } catch (IOException e) {
            response.put("error", "Invalid JSON data: " + e.getMessage());
        }
        return response;
    }

    // VULNERABILITY: Missing Authentication (CWE-862)
    @DeleteMapping("/admin/users/{userId}")
    public Map<String, Object> deleteUser(@PathVariable int userId) {
        // Vulnerable: No authentication or authorization check!
        users.removeIf(u -> (int) u.get("id") == userId);

        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "User deleted");
        return response;
    }

    // VULNERABILITY: Insecure Direct Object Reference (IDOR) (CWE-639)
    @GetMapping("/users/{userId}")
    public Map<String, Object> getUser(@PathVariable int userId) {
        // Vulnerable: No authorization check - any user can view any user's data
        for (Map<String, Object> user : users) {
            if ((int) user.get("id") == userId) {
                return user;
            }
        }

        Map<String, Object> response = new HashMap<>();
        response.put("error", "User not found");
        return response;
    }

    // VULNERABILITY: XML External Entity (XXE) Injection (CWE-611)
    @PostMapping("/parse-xml")
    public Map<String, Object> parseXml(@RequestBody String xmlData) {
        Map<String, Object> response = new HashMap<>();
        try {
            // Vulnerable: XML parser without XXE protection
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(new ByteArrayInputStream(xmlData.getBytes()));

            response.put("result", "XML parsed successfully");
            response.put("root", document.getDocumentElement().getNodeName());
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        return response;
    }

    // VULNERABILITY: YAML Deserialization (CWE-502)
    @PostMapping("/parse-yaml")
    public Map<String, Object> parseYaml(@RequestBody Map<String, String> request) {
        Map<String, Object> response = new HashMap<>();
        try {
            String yamlContent = request.get("yamlContent");
            // Vulnerable: YAML parsing can execute arbitrary code
            Yaml yaml = new Yaml();
            Object parsed = yaml.load(yamlContent);

            response.put("result", parsed);
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        return response;
    }

    // VULNERABILITY: Mass Assignment (CWE-915)
    @PostMapping("/register")
    public Map<String, Object> register(@RequestBody Map<String, Object> userData) {
        // Vulnerable: Directly assigning all properties from user input
        Map<String, Object> newUser = new HashMap<>();
        newUser.put("id", users.size() + 1);
        newUser.putAll(userData);  // Attacker could set role: 'admin'

        users.add(newUser);

        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("user", newUser);
        return response;
    }

    // VULNERABILITY: Sensitive Data Exposure (CWE-200)
    @GetMapping("/debug")
    public Map<String, Object> debug() {
        // Vulnerable: Exposes sensitive environment variables and secrets
        Map<String, Object> response = new HashMap<>();
        response.put("environment", System.getenv());
        response.put("properties", System.getProperties());
        response.put("jwt_secret", VulnerableApplication.JWT_SECRET);
        response.put("admin_password", VulnerableApplication.ADMIN_PASSWORD);
        response.put("db_password", VulnerableApplication.DB_PASSWORD);
        response.put("api_key", VulnerableApplication.API_KEY);
        response.put("users", users);
        return response;
    }

    // VULNERABILITY: Insecure Randomness (CWE-330)
    @GetMapping("/token")
    public Map<String, Object> getToken() {
        // Vulnerable: Random is not cryptographically secure
        Random random = new Random();
        String token = "";
        for (int i = 0; i < 16; i++) {
            token += (char) ('a' + random.nextInt(26));
        }

        Map<String, Object> response = new HashMap<>();
        response.put("token", token);
        return response;
    }
    
    private static final Map<String, String> ALLOWED_REDIRECTS = Map.of(
        "home", "/",
        "search", "/search",
        "files", "/files"
    );

    @GetMapping("/redirect")
    public void redirect(@RequestParam String url, HttpServletResponse response) throws IOException {
        String targetUrl = ALLOWED_REDIRECTS.get(url);
        if (targetUrl == null) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid redirect URL");
            return;
        }
        response.sendRedirect(targetUrl);
    }

    // VULNERABILITY: Information Disclosure through Error Messages (CWE-209)
    @GetMapping("/error-test")
    public Map<String, Object> errorTest() {
        Map<String, Object> response = new HashMap<>();
        try {
            throw new Exception("Database connection failed: jdbc:mysql://admin:password@localhost:3306/mydb");
        } catch (Exception e) {
            // Vulnerable: Exposes sensitive information in error message
            response.put("error", e.getMessage());
            response.put("stackTrace", Arrays.toString(e.getStackTrace()));
        }
        return response;
    }

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @PostMapping("/hash")
    public Map<String, Object> hashPassword(@RequestBody Map<String, String> request) {
        Map<String, Object> response = new HashMap<>();
        try {
            String password = request.get("password");
            if (password == null || password.isEmpty()) {
                response.put("error", "Password is required");
                return response;
            }

            byte[] salt = new byte[16];
            SECURE_RANDOM.nextBytes(salt);

            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = factory.generateSecret(spec).getEncoded();

            response.put("salt", Base64.getEncoder().encodeToString(salt));
            response.put("hash", Base64.getEncoder().encodeToString(hash));
            response.put("algorithm", "PBKDF2WithHmacSHA256");
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            response.put("error", e.getMessage());
        }
        return response;
    }

    @GetMapping("/health")
    public Map<String, String> health() {
        Map<String, String> response = new HashMap<>();
        response.put("status", "running");
        response.put("vulnerabilities", "many");
        return response;
    }
}
