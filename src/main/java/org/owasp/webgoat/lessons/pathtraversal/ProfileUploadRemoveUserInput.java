package org.owasp.webgoat.lessons.pathtraversal;

import static org.springframework.http.MediaType.ALL_VALUE;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import java.nio.file.Path;
import java.nio.file.Paths;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.WebSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@AssignmentHints({
  "path-traversal-profile-remove-user-input.hint1",
  "path-traversal-profile-remove-user-input.hint2",
  "path-traversal-profile-remove-user-input.hint3"
})
public class ProfileUploadRemoveUserInput extends ProfileUploadBase {

  private final Path rootLocation;

  public ProfileUploadRemoveUserInput(
      @Value("${webgoat.server.directory}") String webGoatHomeDirectory, WebSession webSession) {
    super(webGoatHomeDirectory, webSession);
    this.rootLocation = Paths.get(webGoatHomeDirectory);
  }

  @PostMapping(
      value = "/PathTraversal/profile-upload-remove-user-input",
      consumes = ALL_VALUE,
      produces = APPLICATION_JSON_VALUE)
  @ResponseBody
  public AttackResult uploadFileHandler(
      @RequestParam("uploadedFileRemoveUserInput") MultipartFile file) {
    try {
      // Sanitize the file name and generate a new one to prevent path traversal
      String originalFileName = file.getOriginalFilename();
      String safeFileName = java.util.UUID.randomUUID().toString(); // Generating a safe file name
      Path destinationFile =
          this.rootLocation.resolve(Paths.get(safeFileName)).normalize().toAbsolutePath();

      // Verify the file is not being saved outside of the intended directory
      if (!destinationFile.getParent().equals(this.rootLocation.toAbsolutePath())) {
        throw new SecurityException("Cannot store file outside the current directory.");
      }

      // Save the file
      file.transferTo(destinationFile);

      // Process the file as needed
      return super.execute(file, safeFileName);
    } catch (Exception e) {
      throw new RuntimeException("Could not store the file. Error: " + e.getMessage());
    }
  }
}
