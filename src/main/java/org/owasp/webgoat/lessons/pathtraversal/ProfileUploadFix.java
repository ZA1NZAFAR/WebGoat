package org.owasp.webgoat.lessons.pathtraversal;

import static org.springframework.http.MediaType.ALL_VALUE;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import java.nio.file.Path;
import java.nio.file.Paths;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.WebSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@AssignmentHints({
  "path-traversal-profile-fix.hint1",
  "path-traversal-profile-fix.hint2",
  "path-traversal-profile-fix.hint3"
})
public class ProfileUploadFix extends ProfileUploadBase {

  private final Path rootLocation;

  public ProfileUploadFix(
      @Value("${webgoat.server.directory}") String webGoatHomeDirectory, WebSession webSession) {
    super(webGoatHomeDirectory, webSession);
    this.rootLocation = Paths.get(webGoatHomeDirectory).toAbsolutePath().normalize();
  }

  @PostMapping(
      value = "/PathTraversal/profile-upload-fix",
      consumes = ALL_VALUE,
      produces = APPLICATION_JSON_VALUE)
  @ResponseBody
  public AttackResult uploadFileHandler(
      @RequestParam("uploadedFileFix") MultipartFile file,
      @RequestParam(value = "fullNameFix", required = false) String fullName) {
    // Generate a safe file name to avoid using user input directly
    String safeFileName = java.util.UUID.randomUUID().toString();
    // Use the safe file name for storage and any further processing
    return super.execute(file, safeFileName);
  }

  @GetMapping("/PathTraversal/profile-picture-fix")
  @ResponseBody
  public ResponseEntity<?> getProfilePicture() {
    return super.getProfilePicture();
  }
}
