package org.owasp.webgoat.lessons.sqlinjection.introduction;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(
    value = {"SqlStringInjectionHint4-1", "SqlStringInjectionHint4-2", "SqlStringInjectionHint4-3"})
public class SqlInjectionLesson4 extends AssignmentEndpoint {

  private final LessonDataSource dataSource;

  public SqlInjectionLesson4(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack4")
  @ResponseBody
  public AttackResult completed(@RequestParam String inputParameter) {
    return injectableQuery(inputParameter);
  }

  protected AttackResult injectableQuery(String inputParameter) {
    String query =
        "SELECT phone FROM employees WHERE someColumn = ?"; // Adjust based on your SQL logic
    try (Connection connection = dataSource.getConnection();
        PreparedStatement preparedStatement =
            connection.prepareStatement(
                query, ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY)) {

      preparedStatement.setString(
          1, inputParameter); // dynamically set the input parameter to the query
      ResultSet results = preparedStatement.executeQuery();
      StringBuilder output = new StringBuilder();

      if (results.first()) {
        output.append("<span class='feedback-positive'>Query Executed Successfully</span>");
        return success(this).output(output.toString()).build();
      } else {
        return failed(this).output("No data found").build();
      }
    } catch (SQLException sqle) {
      return failed(this).output(sqle.getMessage()).build();
    } catch (Exception e) {
      return failed(this).output(this.getClass().getName() + " : " + e.getMessage()).build();
    }
  }
}
