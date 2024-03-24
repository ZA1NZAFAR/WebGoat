package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static java.sql.ResultSet.CONCUR_READ_ONLY;
import static java.sql.ResultSet.TYPE_SCROLL_INSENSITIVE;

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
@AssignmentHints(value = {"SqlStringInjectionHint3-1", "SqlStringInjectionHint3-2"})
public class SqlInjectionLesson3 extends AssignmentEndpoint {

  private final LessonDataSource dataSource;

  public SqlInjectionLesson3(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack3")
  @ResponseBody
  public AttackResult completed(@RequestParam String lastName) {
    return injectableQuery(lastName);
  }

  protected AttackResult injectableQuery(String lastName) {
    String secureQuery = "SELECT * FROM employees WHERE last_name = ?";
    try (Connection connection = dataSource.getConnection()) {
      try (PreparedStatement statement =
          connection.prepareStatement(secureQuery, TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY)) {
        statement.setString(1, lastName);
        ResultSet results = statement.executeQuery();
        StringBuilder output = new StringBuilder();
        // Check if any result is found
        if (results.next()) {
          // Assuming generateTable is a method that generates a HTML table from the ResultSet
          String table = SqlInjectionLesson8.generateTable(results);
          output.append("<span class='feedback-positive'>Query executed successfully.</span>");
          output.append(table);
          return success(this).output(output.toString()).build();
        } else {
          return failed(this).output("No employee found with the last name: " + lastName).build();
        }
      } catch (SQLException sqle) {
        return failed(this).output(sqle.getMessage()).build();
      }
    } catch (Exception e) {
      return failed(this).output(this.getClass().getName() + " : " + e.getMessage()).build();
    }
  }
}
