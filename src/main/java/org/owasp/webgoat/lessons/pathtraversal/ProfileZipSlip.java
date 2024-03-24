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
import java.util.UUID;
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
  public AttackResult uploadFileHandler(@RequestParam("uploadedFileZipSlip") MultipartFile file)
      throws IOException {
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
    Path tmpZipDirectory = Files.createTempDirectory("webgoat");
    cleanupAndCreateDirectoryForUser();
    byte[] currentImage = getProfilePictureAsBase64();

    String safeFilename = UUID.randomUUID().toString() + ".zip";
    Path uploadedZipFile = tmpZipDirectory.resolve(safeFilename);
    FileCopyUtils.copy(file.getBytes(), uploadedZipFile.toFile());

    try (ZipFile zip = new ZipFile(uploadedZipFile.toFile())) {
      Enumeration<? extends ZipEntry> entries = zip.entries();
      while (entries.hasMoreElements()) {
        ZipEntry entry = entries.nextElement();
        String entryName = sanitizeFileName(entry.getName(), tmpZipDirectory);

        Path resolvedPath = tmpZipDirectory.resolve(entryName).normalize();

        // Verify the resolved path is still within the temporary directory
        if (!resolvedPath.startsWith(tmpZipDirectory)) {
          throw new IOException("Invalid zip entry detected: " + entry.getName());
        }
        if (entry.isDirectory()) {
          Files.createDirectories(resolvedPath);
        } else {
          File parent = resolvedPath.toFile().getParentFile();
          if (parent != null && !parent.exists()) {
            parent.mkdirs();
          }
          try (InputStream is = zip.getInputStream(entry)) {
            Files.copy(is, resolvedPath, StandardCopyOption.REPLACE_EXISTING);
          }
        }
      }
    } catch (IOException e) {
      return failed(this).output(e.getMessage()).build();
    }

    return isSolved(currentImage, getProfilePictureAsBase64());
  }

  private String sanitizeFileName(String fileName, Path destination) {
    fileName = fileName.replace("..", "").replace("\\", "/");

    // Optional: Add more sanitization logic here

    // Prevent directory traversal (sanity check)
    Path resolvedPath = destination.resolve(fileName).normalize();
    if (!resolvedPath.startsWith(destination)) {
      throw new SecurityException("Invalid file path: " + fileName);
    }
    return resolvedPath.getFileName().toString(); // Return only the sanitized file name part
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
