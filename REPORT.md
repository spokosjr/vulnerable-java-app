### 1η Εργασία Τεχνολογία Λογισμικού
>Κωνσταντίνος Σπορίδης
>ΑΜ:
>https://github.com/spokosjr/vulnerable-java-app
>https://sonarcloud.io/project/overview?id=spokosjr_vulnerable-java-app


Κατάλογος Ζητημάτων
- ~~[Ζήτημα 1](#issues1-9)~~
- [Ζήτημα 2]()
- [Ζήτημα 3]()
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

<h5>Τροποποιημένος Κώδικας</h5>

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