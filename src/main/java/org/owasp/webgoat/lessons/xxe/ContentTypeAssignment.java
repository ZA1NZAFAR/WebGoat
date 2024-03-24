package org.owasp.webgoat.lessons.xxe;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Unmarshaller;
import java.io.IOException;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.commons.exec.OS;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.WebSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

@RestController
@AssignmentHints({"xxe.hints.content.type.xxe.1", "xxe.hints.content.type.xxe.2"})
public class ContentTypeAssignment extends AssignmentEndpoint {

  private static final String[] DEFAULT_LINUX_DIRECTORIES = {"usr", "etc", "var"};
  private static final String[] DEFAULT_WINDOWS_DIRECTORIES = {
    "Windows", "Program Files (x86)", "Program Files", "pagefile.sys"
  };

  @Value("${webgoat.server.directory}")
  private String webGoatHomeDirectory;

  @Autowired private WebSession webSession;
  @Autowired private CommentsCache comments;

  @PostMapping(path = "xxe/content-type")
  @ResponseBody
  public AttackResult createNewUser(
      HttpServletRequest request,
      @RequestBody String commentStr,
      @RequestHeader("Content-Type") String contentType) {
    AttackResult attackResult = failed(this).build();

    if (APPLICATION_JSON_VALUE.equals(contentType)) {
      comments.parseJson(commentStr).ifPresent(c -> comments.addComment(c, true));
      attackResult = failed(this).feedback("xxe.content.type.feedback.json").build();
    }

    if (null != contentType && contentType.contains(MediaType.APPLICATION_XML_VALUE)) {
      String error = "";
      try {
        Comment comment = safeParseXml(commentStr);
        comments.addComment(comment, false);
        if (checkSolution(comment)) {
          attackResult = success(this).build();
        }
      } catch (Exception e) {
        error = ExceptionUtils.getStackTrace(e);
        attackResult = failed(this).feedback("xxe.content.type.feedback.xml").output(error).build();
      }
    }

    return attackResult;
  }

  private Comment safeParseXml(String xml)
      throws JAXBException, ParserConfigurationException, SAXException, IOException {
    JAXBContext jc = JAXBContext.newInstance(Comment.class);
    Unmarshaller unmarshaller = jc.createUnmarshaller();

    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
    dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    dbf.setXIncludeAware(false);
    dbf.setExpandEntityReferences(false);

    DocumentBuilder db = dbf.newDocumentBuilder();
    Document document = db.parse(new java.io.ByteArrayInputStream(xml.getBytes()));
    return (Comment) unmarshaller.unmarshal(document);
  }

  private boolean checkSolution(Comment comment) {
    String[] directoriesToCheck =
        OS.isFamilyMac() || OS.isFamilyUnix()
            ? DEFAULT_LINUX_DIRECTORIES
            : DEFAULT_WINDOWS_DIRECTORIES;
    boolean success = false;
    for (String directory : directoriesToCheck) {
      success |= org.apache.commons.lang3.StringUtils.contains(comment.getText(), directory);
    }
    return success;
  }
}
