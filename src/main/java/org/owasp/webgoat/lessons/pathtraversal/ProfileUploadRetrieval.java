package org.owasp.webgoat.lessons.pathtraversal;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.Base64;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.token.Sha512DigestUtils;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "path-traversal-profile-retrieve.hint1",
  "path-traversal-profile-retrieve.hint2",
  "path-traversal-profile-retrieve.hint3",
  "path-traversal-profile-retrieve.hint4",
  "path-traversal-profile-retrieve.hint5",
  "path-traversal-profile-retrieve.hint6"
})
@Slf4j
public class ProfileUploadRetrieval extends AssignmentEndpoint {

  private final File catPicturesDirectory;

  public ProfileUploadRetrieval(@Value("${webgoat.server.directory}") String webGoatHomeDirectory) {
    this.catPicturesDirectory =
        new File(webGoatHomeDirectory, "PathTraversal/cats").getAbsoluteFile();
    this.catPicturesDirectory.mkdirs();
  }

  @PostConstruct
  public void initAssignment() {
    for (int i = 1; i <= 10; i++) {
      try (InputStream is =
          new ClassPathResource("lessons/pathtraversal/images/cats/" + i + ".jpg")
              .getInputStream()) {
        FileCopyUtils.copy(is, new FileOutputStream(new File(catPicturesDirectory, i + ".jpg")));
      } catch (Exception e) {
        log.error("Unable to copy pictures: {}", e.getMessage(), e);
      }
    }
    var secretDirectory = this.catPicturesDirectory.getParentFile();
    try {
      Files.writeString(
          secretDirectory.toPath().resolve("path-traversal-secret.txt"),
          "You found it submit the SHA-512 hash of your username as answer");
    } catch (IOException e) {
      log.error("Unable to write secret in: {}", secretDirectory, e);
    }
  }

  @PostMapping("/PathTraversal/random")
  @ResponseBody
  public AttackResult execute(@RequestParam(value = "secret", required = false) String secret) {
    if (Sha512DigestUtils.shaHex(getWebSession().getUserName()).equalsIgnoreCase(secret)) {
      return success(this).build();
    }
    return failed(this).build();
  }

  @GetMapping("/PathTraversal/random-picture")
  @ResponseBody
  public ResponseEntity<?> getProfilePicture(HttpServletRequest request) {
    try {
      var id = request.getParameter("id");
      if (id == null) {
        id = String.valueOf(RandomUtils.nextInt(1, 11));
      }
      var catPicturePath = this.catPicturesDirectory.toPath().resolve(id + ".jpg").normalize();

      if (!catPicturePath.startsWith(this.catPicturesDirectory.toPath())) {
        return ResponseEntity.badRequest().body("Access denied");
      }

      var catPicture = catPicturePath.toFile();

      if (catPicture.exists()) {
        return ResponseEntity.ok()
            .contentType(MediaType.parseMediaType(MediaType.IMAGE_JPEG_VALUE))
            .body(Base64.getEncoder().encode(FileCopyUtils.copyToByteArray(catPicture)));
      }
      return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Image not found");
    } catch (IOException e) {
      log.error("Image processing error", e);
    }

    return ResponseEntity.badRequest().build();
  }
}
