package org.owasp.webgoat.webwolf;

import static java.util.Comparator.comparing;
import static org.springframework.http.MediaType.ALL_VALUE;

import jakarta.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileTime;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.TimeZone;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

@Controller
@Slf4j
public class FileServer {

  private static final DateTimeFormatter dateTimeFormatter =
      DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

  @Value("${webwolf.fileserver.location}")
  private String fileLocation;

  @Value("${server.address}")
  private String server;

  @Value("${server.servlet.context-path}")
  private String contextPath;

  @Value("${server.port}")
  private int port;

  @RequestMapping(
      path = "/file-server-location",
      consumes = ALL_VALUE,
      produces = MediaType.TEXT_PLAIN_VALUE)
  @ResponseBody
  public String getFileLocation() {
    return fileLocation;
  }

  @PostMapping(value = "/fileupload")
  public ModelAndView importFile(
      @RequestParam("file") MultipartFile myFile, Authentication authentication)
      throws IOException {
    String username = authentication.getName();
    Path userDirectory = Paths.get(fileLocation).resolve(username).normalize();

    // Ensure directory exists and is within the safe location
    if (!userDirectory.startsWith(Paths.get(fileLocation))) {
      throw new SecurityException("Attempted directory traversal attack");
    }
    Files.createDirectories(userDirectory);

    // Sanitize the file name and generate a safe file name
    String originalFileName = myFile.getOriginalFilename();
    String safeFileName =
        Paths.get(originalFileName)
            .getFileName()
            .toString(); // This ensures we only get the file name without any path
    Path destinationFile = userDirectory.resolve(safeFileName);

    // Ensure file is not being saved outside of the intended directory
    if (!destinationFile.normalize().startsWith(userDirectory)) {
      throw new SecurityException("Cannot store file outside the current directory.");
    }

    myFile.transferTo(destinationFile.toFile());
    log.debug("File saved to {}", destinationFile);

    return new ModelAndView(
        new RedirectView("files", true),
        new ModelMap().addAttribute("uploadSuccess", "File uploaded successful"));
  }

  @GetMapping(value = "/files")
  public ModelAndView getFiles(
      HttpServletRequest request, Authentication authentication, TimeZone timezone) {
    String username = (null != authentication) ? authentication.getName() : "anonymous";
    File userDirectory = new File(fileLocation, username);

    ModelAndView modelAndView = new ModelAndView("files");
    File[] files = userDirectory.listFiles(File::isFile);
    ArrayList<UploadedFile> uploadedFiles = new ArrayList<>();

    if (files != null) {
      for (File file : files) {
        String size = FileUtils.byteCountToDisplaySize(file.length());
        String link = String.format("files/%s/%s", username, file.getName());
        uploadedFiles.add(
            new UploadedFile(file.getName(), size, link, getCreationTime(timezone, file)));
      }
    }

    modelAndView.addObject(
        "files",
        uploadedFiles.stream().sorted(comparing(UploadedFile::creationTime).reversed()).toList());
    modelAndView.addObject("webwolf_url", "http://" + server + ":" + port + contextPath);
    return modelAndView;
  }

  private String getCreationTime(TimeZone timezone, File file) {
    try {
      FileTime creationTime = (FileTime) Files.getAttribute(file.toPath(), "creationTime");
      ZonedDateTime zonedDateTime = creationTime.toInstant().atZone(timezone.toZoneId());
      return dateTimeFormatter.format(zonedDateTime);
    } catch (IOException e) {
      return "unknown";
    }
  }

  record UploadedFile(String name, String size, String link, String creationTime) {}
}
