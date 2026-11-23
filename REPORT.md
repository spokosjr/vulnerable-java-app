### 1η Εργασία Τεχνολογία Λογισμικού
>Κωνσταντίνος Σπορίδης
>
>ΑΜ:
>
>https://github.com/spokosjr/vulnerable-java-app
>
>https://sonarcloud.io/project/overview?id=spokosjr_vulnerable-java-app


Κατάλογος Ζητημάτων
- ~~[Ζήτημα 1](#issues1-9)~~
- ~~[Ζήτημα 2](#issue2)~~
- ~~[Ζήτημα 3](#issue3)~~
- ~~[Ζήτημα 4](#issue4)~~
- ~~[Ζήτημα 5](#issue5)~~
- ~~[Ζήτημα 6](#issue6)~~
- ~~[Ζήτημα 7](#issue7)~~
- ~~[Ζήτημα 8](#ζήτημα-8-issue8)~~
- ~~[Ζήτημα 9](#issues1-9)~~
- ~~[Ζήτημα 10](#issue10)~~
- ~~[Ζήτημα 11](#issue11)~~
- ~~[Ζήτημα 12](#issue12)~~
- [Ζήτημα 13](#issue13)

Δυστυχώς τα issues 11,12 και 13 δεν τα βρήκε ποτέ το SonarQube οπότε με βάση την εκφώνηση της άσκησης βρέθηκαν με Ctrl + F στον κώδικα.


#### Ζήτημα 1# & Ζήτημα 9# {#issues1-9}

>Command Injection via HTTP request parameter in VulnerableController.executeCommand()
>
>Either re-interrupt this method or rethrow the "InterruptedException" that can be caught here.

Στο παρακάτω κομμάτι κώδικα υπάρχουν 2 προβλήματα. 
Αρχικά μία παράμετρος από το HTTP request περνάει αυτούσια σε εκτέλεση shell στο λειτουργικό σύστημα. Οι επιπτώσεις αυτού του προβλήματος είναι ότι οποιοσδήποτε έχει πρόσβαση να στείλει HTTP request έχει πρόσβαση σε shell του συστήματος (με δικαιώματα ίδια με την εφαρμογή java). 
Το 2ο πρόβλημα σε αυτή την μέθοδο είναι η λανθασμένη διαχείριση της InteruptedException, κατά την εκτέλεση της process.waitFor() μπλοκάρεται το τρέχον thread, αν όσο είναι μπλοκαρισμένο σταλεί σήμα διακοπής στο thread η waitFor θα πετάξει InteruptedException αλλά το catch δεν θα κάνει κάτι γιαυτό. Άρα όταν η JVM μηδενίσει το flag δεν θα το ξαναενεργοποιήσει το catch μας οπότε το σύστημα θα συνεχίσει να τρέχει το thread αντί να το κλείσει.

<h5>Αρχικός Κώδικας</h5>

```
// VULNERABILITY: Command Injection (CWE-78)
    @GetMapping("/exec")
    public Map<String, Object> executeCommand(@RequestParam String cmd) {
        Map<String, Object> response = new HashMap<>();
        try {
            // Vulnerable: User input directly in shell command
            Process process = Runtime.getRuntime().exec(cmd);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            process.waitFor();

            response.put("success", true);
            response.put("output", output.toString());
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        return response;
    }
```


Έγιναν οι παρακάτω αλλαγές:

- private static final Map<String, List<String>> ALLOWED_COMMANDS
Ορισμός σταθερής λίστας επιτρεπόμενων εντολών

- List<String> command = ALLOWED_COMMANDS.get(cmd);
Αντί να σταλεί η είσοδος του χρήστη στο shell στέλνεται (αν βρεθεί αντιστοιχία) η τιμή από την λίστα

- if (command == null) { ... return response; }
Αν δεν βρεθεί αντιστοιχία στην λίστα, επιστρέφεται σφάλμα Command not allowed και δεν εκτελέιται τίποτα

- ProcessBuilder pb = new ProcessBuilder(command);
Δημιοργία ProcessBuilder με την εντολή σαν όρισμα, σε αντίθεση με το Runtime.exec() δεν ερμηνέυει ειδικούς χαρακτήρες οπότε άλλο ένα επίπεδο ασφάλειας

- try (BufferedReader reader = new BufferedReader())
Χρησιμοποίησα την try-with-resources για να αποφύγω διαρροή μνήμης διότι κλέινει αυτόματα τον reader όταν τελειώσει το block.

- catch (InterruptedException e) { Thread.currentThread().interrupt(); }
Εδώ πιάνεται ξεχωριστά η InterruptedException και επαναφέρεται το flag. (Ζήτημα 9)

- catch (IOException e) { response.put("error", e.getMessage()); }
Εδώ πιάνει συγκεκριμένα τα IOException που μπορεί να πετάξουν τα pb.start() και reader.readLine()

<h5>Τροποποιημένος Κώδικας</h5>

```
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
```

#### Ζήτημα 2# {#issue2}

>Path Traversal via HTTP request parameter in VulnerableController.getFile()

Στο παρακάτω κομμάτι κώδικα υπάρχει πρόβλημα Path Traversal. Η getFile() παίρνει το filename απεθιείας από το HTTP request και την κολλάει στο τέλος του path του /uploads/ χωρίς έλεγχο. Αυτό επιτρέπει στον χρήστη να γράψει σαν filename "../arxeio" και να του επιστραφεί το περιεχόμενο του αρχείου που είναι στον γονικό φάκελο του uploads. Οπότε έτσι έχει πρόσβαση ανάγνωσης οποιουδήποτε αρχείου στο δίσκο έχει δικαιώματα ανάγνωσης η εφαρμογή Java.

<h5>Αρχικός Κώδικας</h5>

```
import java.nio.file.Paths;


// VULNERABILITY: Path Traversal (CWE-22)
    @GetMapping("/files")
    public Map<String, Object> getFile(@RequestParam String filename) {
        Map<String, Object> response = new HashMap<>();
        try {
            // Vulnerable: No sanitization of file path
            String filePath = System.getProperty("user.dir") + "/uploads/" + filename;
            String content = new String(Files.readAllBytes(Paths.get(filePath)));
            response.put("content", content);
        } catch (IOException e) {
            response.put("error", "File not found");
        }
        return response;
    }
```

Έγιναν οι παρακάτω αλλαγές:

- Αρχικά τροποποιήθηκε το include της import java.nio.file.Paths σε import java.nio.file.* ώστε να μπορεί να χρησιμοποιθεί το Path object.

- Path baseDir = Paths.get()
Δημιουργία path object με το base path σε μορφή absolute path και κανονικοποίηση

- Path targetPath = baseDir.resolve(filename).normalize();
Εδώ γίνεται η ένωση του filane με το path και δημιοργείται το targetPath, με την κανονικοποίηση εκτελούνται και οι χαρακτήρες (.. .) ώστε στο επόμενο βήμα να ελεγχθεί το path. 

- if (!targetPath.startsWith(baseDir))
Εδώ γίνεται ο τελικός έλεγχος του normalized path όπου αν δεν ξεκινάει με το baseDir απορρίπτεται και επιστρέφει σφάλμα.

- String content = new String(Files.readAllBytes(targetPath));
Το Paths.get() δεν χρειάζεται πλέον καθώς το targetPath είναι ήδη Path object.

<h5>Τροποποιημένος Κώδικας</h5>

```
import java.nio.file.*;


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

            String content = Files.readString(targetPath);
            response.put("content", content);
        } catch (IOException e) {
            response.put("error", "File not found");
        }
        return response;
    }

```

#### Ζήτημα 3# {#issue3}

>Path Traversal via HTTP request parameter in VulnerableController.uploadFile()

Στο παρακάτω κομμάτι κώδικα υπάρχει πρόβλημα Path Traversal. Η uploadFile() παίρνει το filename απεθιείας από το HTTP request και την κολλάει στο τέλος του path του /uploads/ χωρίς έλεγχο. Αυτό επιτρέπει στον χρήστη να γράψει σαν filename "../arxeio" και να ανεβάσει το αρχείο στον γονικό φάκελο του uploads. Οπότε έτσι έχει πρόσβαση εγγραφής οπουδήποτε στο δίσκο έχει δικαιώματα εγγραφής η εφαρμογή Java. Αν αντικαταστήσει κάποιο εκτελέσιμο αρχείο μπορεί να επιτευχθεί και remote code execution.

<h5>Αρχικός Κώδικας</h5>

```
    // VULNERABILITY: Unrestricted File Upload (CWE-434)
    @PostMapping("/upload")
    public Map<String, Object> uploadFile(@RequestParam("file") String fileContent,
                                          @RequestParam("filename") String filename) {
        Map<String, Object> response = new HashMap<>();
        try {
            // Vulnerable: No file type validation, no size limits
            String uploadPath = System.getProperty("user.dir") + "/uploads/" + filename;
            Files.write(Paths.get(uploadPath), fileContent.getBytes());

            response.put("success", true);
            response.put("filename", filename);
            response.put("path", uploadPath);
        } catch (IOException e) {
            response.put("error", e.getMessage());
        }
        return response;
    }

```

Οι αλλαγές που έγιναν είναι σχεδόν πανομοιότυπες με το [Ζήτημα 2](#issue2)

- Path baseDir = Paths.get()
Δημιουργία path object με το base path σε μορφή absolute path και κανονικοποίηση

- Path targetPath = baseDir.resolve(filename).normalize();
Εδώ γίνεται η ένωση του filane με το path και δημιοργείται το targetPath, με την κανονικοποίηση εκτελούνται και οι χαρακτήρες (.. .) ώστε στο επόμενο βήμα να ελεγχθεί το path. 

- if (!targetPath.startsWith(baseDir))
Εδώ γίνεται ο τελικός έλεγχος του normalized path όπου αν δεν ξεκινάει με το baseDir απορρίπτεται και επιστρέφει σφάλμα.

- Files.write(targetPath, fileContent.getBytes());
Το Paths.get() δεν χρειάζεται πλέον καθώς το targetPath είναι ήδη Path object.


<h5>Τροποποιημένος Κώδικας</h5>

```
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

            Files.writeString(targetPath, fileContent);

            response.put("success", true);
            response.put("filename", filename);
            response.put("path", targetPath.toString());
        } catch (IOException e) {
            response.put("error", e.getMessage());
        }
        return response;
    }
```

#### Ζήτημα 4# {#issue4}

>Reflected XSS via HTTP request parameter in VulnerableController.search()

Στο παρακάτω κομμάτι κώδικα υπάρχει πρόβλημα cross site scripting, δηλαδή η είσοδος του χρήστη μέσω του query ενσωματώνεται αυτούσια στον κώδικα html χωρίς κωδικοποίηση. Αυτό έχει ως αποτέλεσμα ενας χρήστης να μπορεί να δημιουργήσει url με κακόβουλο κώδικα μέσα που θα εκτελεστεί στον browser όποιου το πατήσει. Με αυτό τον τρόπο μπορέι να γίνει επίθεση Session Hijacking κλέβοντας tokens από το localStorage του browser και πολλά ακόμα.

<h5>Αρχικός Κώδικας</h5>

```
    // VULNERABILITY: Cross-Site Scripting (XSS) (CWE-79)
    @GetMapping("/search")
    public String search(@RequestParam String query) {
        // Vulnerable: Reflects user input without sanitization
        return "<h1>Search Results for: " + query + "</h1>";
    }

```

Έγιναν οι παρακάτω αλλαγές:

- Αρχικά προστέθηκε στα imports το  import org.springframework.web.util.HtmlUtils;

- String safeQuery = HtmlUtils.htmlEscape(query);
Με αυτή την μέθοδο όλοι οι ειδικοί χαρακτήρες της HTML μετατρέπονται σε character references πχ το & θα γίνει &amp ; ώστε κατά την επιστροφή στον κώδικα HTML να μην εκτελείται κάποιο script και απλά να εμφανίζονται οι χαρακτήρες &lt;script&gt; 

<h5>Τροποποιημένος Κώδικας</h5>

```
    import org.springframework.web.util.HtmlUtils;


    @GetMapping("/search")
    public String search(@RequestParam String query) {
        String safeQuery = HtmlUtils.htmlEscape(query);
        return "<h1>Search Results for: " + safeQuery + "</h1>";
    }

```

#### Ζήτημα 5# {#issue5}

>Insecure Deserialization via HTTP request body in VulnerableController.deserialize()

Στο παρακάτω κομμάτι κώδικα υπάρχει πρόβλημα Insecure Deserialization. Η deserialize() παίρνει δεδομένα απευθείας από το HTTP request και τα περνάει στο ObjectInputStream χωρίς κανέναν έλεγχο για το είδος ή το περιεχόμενο του αντικειμένου. Αυτό επιτρέπει σε έναν κακόβουλο χρήστη να στείλει ειδικά διαμορφωμένο Java serialized object και, κατά την αποσειριοποίηση, να ενεργοποιηθούν επικίνδυνες μέθοδοι μέσα σε classes που υπάρχουν στο classpath της εφαρμογής. Οι επιπτώσεις μπορεί να είναι Remote Code Execution με τα δικαιώματα της εφαρμογής, εκτέλεση μη αναμενόμενων ενεργειών, καθώς και Denial of Service μέσω αντικειμένων που καταναλώνουν υπερβολικούς πόρους. Επειδή το endpoint δεν κάνει authentication ή validation των δεδομένων, οποιοσδήποτε μπορεί να επιχειρήσει την επίθεση στέλνοντας ένα HTTP request.

<h5>Αρχικός Κώδικας</h5>

```
    // VULNERABILITY: Insecure Deserialization (CWE-502)
    @PostMapping("/deserialize")
    public Map<String, Object> deserialize(@RequestBody byte[] data) {
        Map<String, Object> response = new HashMap<>();
        try {
            // Vulnerable: Deserializing untrusted data
            ByteArrayInputStream bis = new ByteArrayInputStream(data);
            ObjectInputStream ois = new ObjectInputStream(bis);
            Object obj = ois.readObject();
            ois.close();

            response.put("result", obj.toString());
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        return response;
    }

```

Έγιναν οι παρακάτω αλλαγές:

- Αρχικά αφαιρέθηκε η χρήση των ByteArrayInputStream και ObjectInputStream, επειδή το native Java deserialization δεν πρέπει να χρησιμοποιείται για δεδομένα που προέρχονται από τον χρήστη.

- ObjectMapper mapper = new ObjectMapper();
Δημιουργία ObjectMapper για την ανάγνωση δεδομένων JSON αντί για Java serialized objects. Το JSON είναι μορφή δεδομένων και δεν περιέχει τις ίδιες δυνατότητες εκτέλεσης κώδικα που έχει η αποσειριοποίηση αυθαίρετων Java objects.

- Object obj = mapper.readValue(data, Map.class);
Τα δεδομένα μετατρέπονται αποκλειστικά σε Map, οπότε δεν επιτρέπεται η δημιουργία αυθαίρετου Java object ή η φόρτωση class από το input του χρήστη. Αν τα δεδομένα δεν είναι έγκυρο JSON, η μετατροπή αποτυγχάνει.

- catch (IOException e) { ... }
Πιάνεται συγκεκριμένα η IOException που μπορεί να προκύψει όταν τα δεδομένα δεν είναι έγκυρο JSON και επιστρέφεται μήνυμα σφάλματος, χωρίς να διακόπτεται η λειτουργία της εφαρμογής.



<h5>Τροποποιημένος Κώδικας</h5>

```
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
```

#### Ζήτημα 6# {#issue6}

>Open Redirect via HTTP request parameter in VulnerableController.redirect()

Στο παρακάτω κομμάτι κώδικα υπάρχει πρόβλημα Open Redirect. Αυτό συμβαίνει γιατί ο κώδικας παίρνει αυτούσιο το url από το http request και το στέλνει κατευθείαν στον browser του χρήστη σαν redirect. Αυτό επιτρέπει σε κάποιον κακόβουλο να δημιοργήσει ενα link που ξεκινάει με το domain της εφαρμογής και επειδή φαίνεται έμπιστο στον χρήστη το πατάει αλλά μπορεί να καταλήγει σε phishing site, επίσης μπορεί να γίνει υποκλοπή token από το local storage του browser.

<h5>Αρχικός Κώδικας</h5>

```
    // VULNERABILITY: Open Redirect (CWE-601)
    @GetMapping("/redirect")
    public void redirect(@RequestParam String url, HttpServletResponse response) throws IOException {
        // Vulnerable: No validation of redirect URL
        response.sendRedirect(url);
    }
```

Η επίλυση είναι παρόμοια με το [Ζήτημα 1](#issues1-9). Συγκεκριμένα έγιναν οι παρακάτω αλλαγές:

- private static final Map<String, String> ALLOWED_REDIRECTS
Ορισμός σταθερής λίστας επιτρεπόμενων redirect

- String targetUrl = ALLOWED_REDIRECTS.get(url);
Αντί να σταλεί η είσοδος του χρήστη στον browser σαν redirect στέλνεται (αν βρεθεί αντιστοιχία) η τιμή από την λίστα

- if (targetUrl == null) { ... return response; }
Αν δεν βρεθεί αντιστοιχία στην λίστα, επιστρέφεται σφάλμα HTTP 400 Bad Request και δεν εκτελέιται redirect

- response.sendRedirect(targetUrl);
Εκτελείται redirect με την τιμή από την λίστα μας.

<h5>Τροποποιημένος Κώδικας</h5>

```
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
```

#### Ζήτημα 7# {#issue7}

>Make sure this weak hash algorithm is not used in a sensitive context here.

Στο παρακάτω κομμάτι κώδικα υπάρχει πρόβλημα από την χρήση του αλγορίθμου MD5. Ο αλγόριθμος αυτός, παρουσιάζει κρυπτογραφικές ευπάθειες όπως collisions και λόγω του ταχύτατου υπολογισμού του είναι ακατάλληλος για χρήση σε passwords. Σε μια σύγχρονη GPU μπορούν με bruteforce να σπάσουν οι περισσότεροι κωδικοί σε ελάχιστο χρόνο.

<h5>Αρχικός Κώδικας</h5>

```
    // VULNERABILITY: Weak Cryptography (CWE-327)
    @PostMapping("/hash")
    public Map<String, Object> hashPassword(@RequestBody Map<String, String> request) {
        Map<String, Object> response = new HashMap<>();
        try {
            String password = request.get("password");
            // Vulnerable: Using weak hash algorithm (MD5)
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(password.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                hexString.append(String.format("%02x", b));
            }

            response.put("hash", hexString.toString());
            response.put("algorithm", "MD5");
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        return response;
    }
```
Αντικαταστάθηκε ο MD5 με τον PBKDF2WithHmacSHA256, στον κώδικα έγιναν οι παρακάτω αλλαγές:

- private static final SecureRandom SECURE_RANDOM = new SecureRandom();
Δημιουργία του SECURE_RANDOM object για επαναχρησιμοποίηση στον κώδικα και επίλυση του (Save and re-use this "Random".) issue που δημιουργήθηκε με το προηγούμενο commit.
Έγινε αλλαγή και στην getToken για χρήση του SECURE_RANDOM object καθώς εμφανοζόνταν και εκεί το ίδιο issue.

- if (password == null || password.isEmpty())
Έλεγχος οτι δώθηκε κωδικός για να αποφύγουμε το NullPointerException

- byte[] salt = new byte[16]; και SECURE_RANDOM.nextBytes(salt);
Δημιουργία Κρυπτογραφικά ασφαλές salt 16 bytes

- PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
Ορίζουμε τις παραμέτρους του αλγορίθμου, τον κωδικό, το salt, τις επαναλήψεις και το μήκος της εξόδου.

- SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
Επιλογή του αλγορίθμου PBKDF2WithHmacSHA256

- byte[] hash = factory.generateSecret(spec).getEncoded();
Εκτελεί το hashing και παίρνει τα bytes του hash.

- Base64.getEncoder().encodeToString()
Κωδικοποίηση του hash και του salt σε Base64 για να σταλέι σε JSON

- catch (NoSuchAlgorithmException | InvalidKeySpecException e)
Πιάνει τα συγκεκριμένα exceptions που μπορεί να προκύψουν αντί για το γενικό.

<h5>Τροποποιημένος Κώδικας</h5>

```
import java.security.spec.InvalidKeySpecException;
import javax.crypto.spec.PBEKeySpec;
import java.security.*;
import javax.crypto.*;

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
```

#### Ζήτημα 8# {#issue8}

>Make sure that enabling CORS is safe here.

Στο παρακάτω κομμάτι κώδικα υπάρχει πρόβλημα με τις ρυθμίσεις του CORS. Συγκεκριμένα επιτρέπονται request από οποιοδήποτε domain με όλες τις μεθόδους http Και όλα τα headers, ταυτόχρονα είναι ενεργό και το allowCredentials. Αυτό επιτρέπει σε οποιοδήποτε domain να διαβάζει δεδομένα από την εφαρμογή μας (μέσω του browser του χρήστη) και λόγω του allowCredentials μπορεί να εκτελέσει εντολές για λογαριασμό του χρήστη λαμβάνοντας πίσω και την απάντηση.

<h5>Αρχικός Κώδικας</h5>

```
@Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedOrigins("*")  // Allows any origin
                        .allowedMethods("*")  // Allows all HTTP methods
                        .allowedHeaders("*")  // Allows all headers
                        .allowCredentials(true);  // Dangerous with wildcard origin
            }
        };
    }
```

Έγιναν οι παρακάτω αλλαγές:
- .allowedOrigins("https://trusted.example.com")
Η πιο σημαντική αλλαγή καθώς επιτρέπει μόνο σε συγκεκριμένο domain να έχει πρόσβαση στα δεδομένα της εφαρμογής μας

- .allowedMethods("GET", "POST", "PUT", "DELETE")
Επιτρέπει συγκεκριμένες μεθόδους HTTP

- .allowedHeaders("Content-Type", "Authorization")
Επιτρέπει συγκεκριμένα headers

- .allowCredentials(true)
Τώρα είναι ασφαλής η χρήση του εφόσον κάθε επιτρεπόμενο request Θα προέρχεται από έμπιστο domains


<h5>Τροποποιημένος Κώδικας</h5>

```
@Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedOrigins("https://trusted.example.com")
                        .allowedMethods("GET", "POST", "PUT", "DELETE")
                        .allowedHeaders("Content-Type", "Authorization")
                        .allowCredentials(true);
            }
        };
    }
```

#### Ζήτημα 10# {#issue10}

>Make sure this debug feature is deactivated before delivering the code in production.

Στο παρακάτω κομμάτι του config αρχείου application.properties είναι ενεργοποιημένο το debug καθώς τα logging επίπεδα της εφαρμογής και του spring. 

<h5>Αρχικός Κώδικας</h5>

```
# VULNERABILITY: Debug mode enabled (CWE-489)
debug=true
logging.level.root=DEBUG
logging.level.org.springframework.web=DEBUG

```

Έγιναν οι παρακάτω αλλαγές:

- Αλλαγή του boolean debug από true σε false

- logging.level.root=INFO περιορισμός του logging σε κανονικά μηνύματα πχ εκκίνηση εφαρμογής και σημαντικά συμβάντα

- logging.level.org.springframework.web=WARN περιορισμός των logs του spring web σε προειδοποιήσεις και σφάλματα


<h5>Τροποποιημένος Κώδικας</h5>

```
debug=false
logging.level.root=INFO
logging.level.org.springframework.web=WARN
```

#### Ζήτημα 11# {#issue11}

Βρέθηκε με ctrl + F χρησιμοποιώντας "System.out"

>Replace this use of System.out by a logger.

Στο παρακάτω κομμάτι κώδικα υπάρχει πρόβλημα με την εκτύπωση του query με System.out.println, το print δεν έχει timestamps ούτε log levels.

<h5>Αρχικός Κώδικας</h5>

```
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
```

Έγιναν οι παρακάτω αλλαγές:

- import org.slf4j.*; το slf4j υπάρχει στο spingboot και έχει ενσωματωμένο Logger

- private static final Logger logger = LoggerFactory.getLogger(VulnerableController.class);
Δημιουργία logger για την κλάση VulnerableController οπότε κάθε μήνμυα θα φέρει αυτόματα ώρα, επίπεδο και πηγή.

- logger.debug("Query: {}", query);
Αντικατάσταση System.out.println με τον logger σε επίπεδο debug.

<h5>Τροποποιημένος Κώδικας</h5>

```
    import org.slf4j.*;



    private static final Logger logger = LoggerFactory.getLogger(VulnerableController.class);

    // VULNERABILITY: SQL Injection (CWE-89)
    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody Map<String, String> credentials) {
        String username = credentials.get("username");
        String password = credentials.get("password");

        // Vulnerable: Direct string concatenation simulating SQL injection
        String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        
        logger.debug("Query: {}", query);

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

```

#### Ζήτημα 12# {#issue12}

Βρέθηκε με ctrl + F χρησιμοποιώντας "(Exception e)"
Υπήρξαν αρκετά αποτελέσματα και επέλεξα την errorTest().

>Replace generic exceptions with specific library exceptions or a custom exception.

Στο παρακάτω κομμάτι κώδικα υπάρχουν 2 προβλήματα. Αρχικά το μήυμα σφάλματος εμπεριέχει ευαίσθητα credentials. Το κύριο πρόβλημα είναι το γενικό catch (Exception e) που δυσκολέυει την διαχείριση του σφάλματος από τον κώδικα που καλεί την errorTest().

<h5>Αρχικός Κώδικας</h5>

```
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
    
```

Έγιναν οι παρακάτω αλλαγές:

- throw new SQLException("Database connection failed");
Αφαιρέθηκαν τα credentials από το μήνυμα του exception

- catch (SQLException e)
Αλλάχθηκε το γενικό exception με το SQLException 

<h5>Τροποποιημένος Κώδικας</h5>

```
   @GetMapping("/error-test")
    public Map<String, Object> errorTest() {
        Map<String, Object> response = new HashMap<>();
        try {
            throw new SQLException("Database connection failed");
        } catch (SQLException e) {
            response.put("error", e.getMessage());
        }
        return response;
    }

```