import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.*;

public class PasswordVaultCLI {

    private static final Path VAULT_FILE = Paths.get("vault.dat");
    private static final Path AUDIT_LOG = Paths.get("audit_log.txt");
    private static final Path EXPORT_CSV = Paths.get("export.csv");
    private static final String MAGIC = "SPVLTv1";
    private static final byte VERSION = 1;
    private static final int SALT_LEN = 16;
    private static final int IV_LEN = 12;
    private static final int KEY_LEN = 256;
    private static final int PBKDF2_ITER = 100_000;
    private static final int GCM_TAG_BITS = 128;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Map<String, PasswordEntry> entries = new HashMap<>();
    private final CipherStrategy cipher = new AesGcmCipherStrategy();
    private SecretKeySpec unlockedKey = null;
    private byte[] currentSalt = null;
    private byte[] currentIv = null;
    private final Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) {
        new PasswordVaultCLI().start();
    }

    private void start() {
        printHeader();
        char[] master = promptForMasterPassword();
        if (master == null || master.length == 0) {
            println("Master password required. Exiting.");
            return;
        }
        try {
            if (Files.exists(VAULT_FILE)) {
                loadVault(master);
                println("Vault unlocked. " + entries.size() + " entries loaded.");
            } else {
                currentSalt = new byte[SALT_LEN];
                RANDOM.nextBytes(currentSalt);
                unlockedKey = deriveKey(master, currentSalt);
                println("New vault created. No entries yet.");
            }
            commandLoop();
        } catch (AuthFailedException e) {
            println("Authentication failed: " + e.getMessage());
        } catch (Exception e) {
            println("Failed to open vault: " + e.getMessage());
            e.printStackTrace();
        } finally {
            Arrays.fill(master, '\0');
            wipeKey();
        }
    }

    private void printHeader() {
        println("┌────────────────────────────────────────────┐");
        println("│         Simple Password Vault (CLI)        │");
        println("└────────────────────────────────────────────┘");
    }

    private char[] promptForMasterPassword() {
        return readPasswordMaskedPrompt("Master password: ");
    }

    private void commandLoop() {
        while (true) {
            System.out.println();
            System.out.println("====== PASSWORD VAULT ======");
            System.out.println("1. Add Entry");
            System.out.println("2. Get Entry");
            System.out.println("3. Delete Entry");
            System.out.println("4. List Entries");
            System.out.println("5. Export Vault (CSV)");
            System.out.println("6. Help");
            System.out.println("7. Quit");
            System.out.print("Select an option (1 (to) 7): ");
            String choice = scanner.nextLine().trim();
            try {
                switch (choice) {
                    case "1":
                        handleAdd();
                        break;
                    case "2":
                        handleGet();
                        break;
                    case "3":
                        handleDelete();
                        break;
                    case "4":
                        handleList();
                        break;
                    case "5":
                        handleExport();
                        break;
                    case "6":
                        printHelp();
                        break;
                    case "7":
                        handleExit();
                        return;
                    default:
                        println("Invalid option. Please choose a number between 1 and 7.");
                }
            } catch (Exception e) {
                println("Error: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    private void printHelp() {
        println("");
        println("1. Add Entry   - Stores a new site password");
        println("2. Get Entry   - Retrieves a stored password");
        println("3. Delete Entry- Removes an entry from the vault");
        println("4. List Entries- Shows saved site keys");
        println("5. Export Vault- Saves vault to CSV (plaintext)");
        println("6. Help        - Shows this menu");
        println("7. Quit        - Save and exit");
    }

    private void handleAdd() throws Exception {
        println("");
        System.out.print("Site key (unique): ");
        String site = scanner.nextLine().trim();
        if (site.isEmpty()) {
            println("Site key cannot be empty.");
            return;
        }
        System.out.print("Username         : ");
        String username = scanner.nextLine().trim();
        char[] pwdChars = readPasswordMaskedPrompt("Password (leave empty to auto-generate): ");
        String password;
        if (pwdChars.length == 0) {
            password = generatePassword(16);
            println("Generated password: " + password);
        } else {
            password = new String(pwdChars);
            Arrays.fill(pwdChars, '\0');
        }
        PasswordEntry entry = new PasswordEntry(site, username, password, new Date());
        entries.put(site, entry);
        persistVault();
        logAudit("ADD " + site);
        println("Entry added: " + site);
    }

    private void handleGet() {
        System.out.print("Site key: ");
        String site = scanner.nextLine().trim();
        if (site.isEmpty()) {
            println("Site key cannot be empty.");
            return;
        }
        PasswordEntry e = entries.get(site);
        if (e == null) {
            println("No entry found for: " + site);
            return;
        }
        println("");
        println("── Entry ─────────────────────────");
        println("Site     : " + e.getSite());
        println("Username : " + e.getUsername());
        println("Password : " + e.getPassword());
        println("Updated  : " + e.getUpdatedAt());
        println("────────────────────────────────");
        logAudit("GET " + site);
    }

    private void handleDelete() throws Exception {
        System.out.print("Site key: ");
        String site = scanner.nextLine().trim();
        if (site.isEmpty()) {
            println("Site key cannot be empty.");
            return;
        }
        if (entries.remove(site) != null) {
            persistVault();
            logAudit("DELETE " + site);
            println("Deleted: " + site);
        } else {
            println("No entry found for: " + site);
        }
    }

    private void handleList() {
        if (entries.isEmpty()) {
            println("(no entries)");
            return;
        }
        println("");
        println("Stored entries:");
        int i = 1;
        for (String key : entries.keySet()) {
            println(" " + (i++) + ". " + key);
        }
    }

    private void handleExport() throws Exception {
        try (BufferedWriter w = Files.newBufferedWriter(EXPORT_CSV, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
            w.write("site,username,password,updatedAt\n");
            for (PasswordEntry e : entries.values()) {
                w.write(csvEscape(e.getSite()) + "," + csvEscape(e.getUsername()) + "," +
                        csvEscape(e.getPassword()) + "," + e.getUpdatedAt().getTime() + "\n");
            }
        }
        logAudit("EXPORT " + EXPORT_CSV.toString());
        println("Exported to: " + EXPORT_CSV.toAbsolutePath());
        println("(WARNING: exported CSV is plaintext)");
    }

    private void handleExit() {
        try {
            persistVault();
            logAudit("EXIT");
            println("Exiting... Goodbye!");
        } catch (Exception e) {
            println("Failed to save vault on exit: " + e.getMessage());
        }
    }

    private void loadVault(char[] master) throws Exception {
        try (DataInputStream dis = new DataInputStream(Files.newInputStream(VAULT_FILE, StandardOpenOption.READ))) {
            byte[] magicBytes = new byte[MAGIC.length()];
            dis.readFully(magicBytes);
            String fmagic = new String(magicBytes, StandardCharsets.US_ASCII);
            if (!MAGIC.equals(fmagic)) throw new IOException("Not a recognized vault file");
            int version = dis.readUnsignedByte();
            if (version != VERSION) throw new IOException("Unsupported vault version: " + version);
            int saltLen = dis.readUnsignedByte();
            if (saltLen <= 0 || saltLen > 255) throw new IOException("Invalid salt length");
            currentSalt = new byte[saltLen];
            dis.readFully(currentSalt);
            int ivLen = dis.readUnsignedByte();
            if (ivLen <= 0 || ivLen > 255) throw new IOException("Invalid iv length");
            currentIv = new byte[ivLen];
            dis.readFully(currentIv);
            long ctLen = dis.readLong();
            if (ctLen < 1 || ctLen > Integer.MAX_VALUE) throw new IOException("Invalid ciphertext length");
            byte[] ciphertext = new byte[(int) ctLen];
            dis.readFully(ciphertext);
            unlockedKey = deriveKey(master, currentSalt);
            byte[] plain = cipher.decrypt(ciphertext, unlockedKey, currentIv);
            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(plain))) {
                Object obj = ois.readObject();
                if (obj instanceof Map) {
                    Map<?, ?> m = (Map<?, ?>) obj;
                    entries.clear();
                    for (Map.Entry<?, ?> e : m.entrySet()) {
                        if (e.getKey() instanceof String && e.getValue() instanceof PasswordEntry) {
                            entries.put((String) e.getKey(), (PasswordEntry) e.getValue());
                        }
                    }
                } else {
                    throw new IOException("Unexpected vault contents");
                }
            }
            Arrays.fill(plain, (byte) 0);
            Arrays.fill(ciphertext, (byte) 0);
        }
    }

    private void persistVault() throws Exception {
        byte[] plain;
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(entries);
            oos.flush();
            plain = bos.toByteArray();
        }
        if (currentSalt == null) {
            currentSalt = new byte[SALT_LEN];
            RANDOM.nextBytes(currentSalt);
            if (unlockedKey == null) throw new IllegalStateException("No key available to encrypt");
        }
        currentIv = new byte[IV_LEN];
        RANDOM.nextBytes(currentIv);
        byte[] ciphertext = cipher.encrypt(plain, unlockedKey, currentIv);
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            out.write(MAGIC.getBytes(StandardCharsets.US_ASCII));
            out.write(VERSION);
            out.write(currentSalt.length);
            out.write(currentSalt);
            out.write(currentIv.length);
            out.write(currentIv);
            out.write(longToBytes(ciphertext.length));
            out.write(ciphertext);
            Files.write(VAULT_FILE, out.toByteArray(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        }
        Arrays.fill(plain, (byte) 0);
        Arrays.fill(ciphertext, (byte) 0);
    }

    private SecretKeySpec deriveKey(char[] master, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(master, salt, PBKDF2_ITER, KEY_LEN);
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] key = skf.generateSecret(spec).getEncoded();
            try {
                return new SecretKeySpec(key, "AES");
            } finally {
                Arrays.fill(key, (byte) 0);
            }
        } finally {
            spec.clearPassword();
        }
    }

    private void wipeKey() {
        if (unlockedKey != null) {
            byte[] k = unlockedKey.getEncoded();
            if (k != null) Arrays.fill(k, (byte) 0);
            unlockedKey = null;
        }
    }

    private static long bytesToLong(byte[] b) {
        long v = 0;
        for (int i = 0; i < 8; i++) v = (v << 8) | (b[i] & 0xffL);
        return v;
    }

    private static byte[] longToBytes(long v) {
        byte[] b = new byte[8];
        for (int i = 7; i >= 0; i--) {
            b[i] = (byte) (v & 0xff);
            v >>= 8;
        }
        return b;
    }

    private static String csvEscape(String s) {
        if (s == null) return "";
        if (s.contains(",") || s.contains("\"") || s.contains("\n")) {
            return "\"" + s.replace("\"", "\"\"") + "\"";
        }
        return s;
    }

    private static String generatePassword(int len) {
        String lower = "abcdefghijklmnopqrstuvwxyz";
        String up = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String digits = "0123456789";
        String syms = "!@#$%^&*()-_=+[]{};:,.<>?";
        String charset = lower + up + digits + syms;
        SecureRandom r = new SecureRandom();
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            sb.append(charset.charAt(r.nextInt(charset.length())));
        }
        return sb.toString();
    }

    private char[] readPasswordMaskedPrompt(String prompt) {
        Console console = System.console();
        if (console != null) {
            char[] pwd = console.readPassword(prompt);
            return pwd == null ? new char[0] : pwd;
        } else {
            System.out.print(prompt);
            String line = scanner.nextLine();
            return line == null ? new char[0] : line.toCharArray();
        }
    }

    private static void println(String s) {
        System.out.println(s);
    }

    private void logAudit(String action) {
        try {
            String ts = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
            String line = ts + " - " + action + System.lineSeparator();
            Files.write(AUDIT_LOG, line.getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException ignored) {
        }
    }

    private static String csvEscape(Object o) {
        return csvEscape(String.valueOf(o));
    }

    private static class PasswordEntry implements Serializable {
        private static final long serialVersionUID = 1L;
        private final String site;
        private final String username;
        private final String password;
        private final Date updatedAt;
        PasswordEntry(String site, String username, String password, Date updatedAt) {
            this.site = site;
            this.username = username;
            this.password = password;
            this.updatedAt = updatedAt;
        }
        public String getSite() { return site; }
        public String getUsername() { return username; }
        public String getPassword() { return password; }
        public Date getUpdatedAt() { return updatedAt; }
    }

    private interface CipherStrategy {
        byte[] encrypt(byte[] plain, SecretKeySpec key, byte[] iv) throws Exception;
        byte[] decrypt(byte[] cipherText, SecretKeySpec key, byte[] iv) throws Exception;
    }

    private static class AesGcmCipherStrategy implements CipherStrategy {
        @Override
        public byte[] encrypt(byte[] plain, SecretKeySpec key, byte[] iv) throws Exception {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, iv);
            c.init(Cipher.ENCRYPT_MODE, key, spec);
            return c.doFinal(plain);
        }
        @Override
        public byte[] decrypt(byte[] cipherText, SecretKeySpec key, byte[] iv) throws Exception {
            try {
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, iv);
                c.init(Cipher.DECRYPT_MODE, key, spec);
                return c.doFinal(cipherText);
            } catch (javax.crypto.AEADBadTagException ex) {
                throw new AuthFailedException("Decryption failed: authentication tag mismatch");
            }
        }
    }

    private static class AuthFailedException extends Exception {
        AuthFailedException(String s) { super(s); }
    }
}