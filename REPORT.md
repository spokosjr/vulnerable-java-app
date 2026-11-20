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
- [Ζήτημα 4]()
- [Ζήτημα 5]()
- [Ζήτημα 6]()
- [Ζήτημα 7]()
- [Ζήτημα 8]()
- ~~[Ζήτημα 9](#issues1-9)~~
- [Ζήτημα 10]()
- [Ζήτημα 11]()
- [Ζήτημα 12]()
- [Ζήτημα 13]()


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