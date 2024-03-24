package org.owasp.webgoat.lessons.pathtraversal;

import static org.springframework.http.MediaType.ALL_VALUE;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.WebSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@AssignmentHints({
        "path-traversal-zip-slip.hint1",
        "path-traversal-zip-slip.hint2",
        "path-traversal-zip-slip.hint3",
        "path-traversal-zip-slip.hint4"
})
public class ProfileZipSlip extends ProfileUploadBase {

    public ProfileZipSlip(
            @Value("${webgoat.server.directory}") String webGoatHomeDirectory, WebSession webSession) {
        super(webGoatHomeDirectory, webSession);
    }

    @PostMapping(
            value = "/PathTraversal/zip-slip",
            consumes = ALL_VALUE,
            produces = APPLICATION_JSON_VALUE)
    @ResponseBody
    public AttackResult uploadFileHandler(@RequestParam("uploadedFileZipSlip") MultipartFile file) throws IOException {
        String originalFilename = file.getOriginalFilename();
        if (originalFilename == null || !originalFilename.toLowerCase().endsWith(".zip")) {
            return failed(this).feedback("path-traversal-zip-slip.no-zip").build();
        }
        // Validate the filename
        if (!originalFilename.matches("[a-zA-Z0-9\\.\\-_]+")) {
            return failed(this).feedback("path-traversal-zip-slip.invalid-filename").build();
        }
        return processZipUpload(file);
    }

    private AttackResult processZipUpload(MultipartFile file) throws IOException {
        // Use a secure method to create a temporary directory
        Path tmpZipDirectory = Files.createTempDirectory("webgoat");
        cleanupAndCreateDirectoryForUser();
        byte[] currentImage = getProfilePictureAsBase64();

        Path uploadedZipFile = tmpZipDirectory.resolve(file.getOriginalFilename());
        FileCopyUtils.copy(file.getBytes(), uploadedZipFile.toFile());

        try (ZipFile zip = new ZipFile(uploadedZipFile.toFile())) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry e = entries.nextElement();
                Path outputPath = tmpZipDirectory.resolve(e.getName());
                // Check for path traversal vulnerability
                if (!outputPath.normalize().startsWith(tmpZipDirectory)) {
                    throw new IOException("Invalid zip entry detected: " + e.getName());
                }
                if (e.isDirectory()) {
                    Files.createDirectories(outputPath);
                } else {
                    File parent = outputPath.toFile().getParentFile();
                    if (parent != null) {
                        // Ensure the parent directory is within the expected path
                        if (!parent.toPath().normalize().startsWith(tmpZipDirectory)) {
                            throw new IOException("Invalid parent directory: " + parent);
                        }
                        if (!parent.exists()) {
                            parent.mkdirs();
                        }
                    }
                    try (InputStream is = zip.getInputStream(e)) {
                        Files.copy(is, outputPath, StandardCopyOption.REPLACE_EXISTING);
                    }
                }
            }
        } catch (IOException e) {
            return failed(this).output(e.getMessage()).build();
        }

        return isSolved(currentImage, getProfilePictureAsBase64());
    }

    private AttackResult isSolved(byte[] currentImage, byte[] newImage) {
        if (Arrays.equals(currentImage, newImage)) {
            return failed(this).output("path-traversal-zip-slip.extracted").build();
        }
        return success(this).output("path-traversal-zip-slip.extracted").build();
    }

    @GetMapping("/PathTraversal/zip-slip/")
    @ResponseBody
    public ResponseEntity<?> getProfilePicture() {
        return super.getProfilePicture();
    }

    @GetMapping("/PathTraversal/zip-slip/profile-image/{username}")
    @ResponseBody
    public ResponseEntity<?> getProfilePicture(@PathVariable("username") String username) {
        // Validate the username
        if (!username.matches("[a-zA-Z0-9\\.\\-_]+")) {
            return ResponseEntity.badRequest().build();
        }
        return ResponseEntity.notFound().build();
    }
}
