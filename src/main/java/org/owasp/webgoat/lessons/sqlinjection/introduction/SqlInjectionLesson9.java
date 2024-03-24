package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.hsqldb.jdbc.JDBCResultSet.CONCUR_UPDATABLE;
import static org.hsqldb.jdbc.JDBCResultSet.TYPE_SCROLL_SENSITIVE;

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
    value = {
      "SqlStringInjectionHint.9.1",
      "SqlStringInjectionHint.9.2",
      "SqlStringInjectionHint.9.3",
      "SqlStringInjectionHint.9.4",
      "SqlStringInjectionHint.9.5"
    })
public class SqlInjectionLesson9 extends AssignmentEndpoint {

  private final LessonDataSource dataSource;

  public SqlInjectionLesson9(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack9")
  @ResponseBody
  public AttackResult completed(@RequestParam String name, @RequestParam String auth_tan) {
    return injectableQueryIntegrity(name, auth_tan);
  }

  protected AttackResult injectableQueryIntegrity(String name, String auth_tan) {
    StringBuilder output = new StringBuilder();
    String query = "SELECT * FROM employees WHERE last_name = ? AND auth_tan = ?";
    try (Connection connection = dataSource.getConnection()) {
      try (PreparedStatement statement =
          connection.prepareStatement(query, TYPE_SCROLL_SENSITIVE, CONCUR_UPDATABLE)) {
        statement.setString(1, name);
        statement.setString(2, auth_tan);
        SqlInjectionLesson8.log(connection, query); // Note: logging placeholder query
        ResultSet results = statement.executeQuery();
        if (results.getStatement() != null) {
          if (results.first()) {
            output.append(SqlInjectionLesson8.generateTable(results));
          } else {
            // no results
            return failed(this).feedback("sql-injection.8.no.results").build();
          }
        }
      } catch (SQLException e) {
        System.err.println(e.getMessage());
        return failed(this)
            .output("<br><span class='feedback-negative'>" + e.getMessage() + "</span>")
            .build();
      }

      return checkSalaryRanking(connection, output);

    } catch (Exception e) {
      System.err.println(e.getMessage());
      return failed(this)
          .output("<br><span class='feedback-negative'>" + e.getMessage() + "</span>")
          .build();
    }
  }

  private AttackResult checkSalaryRanking(Connection connection, StringBuilder output) {
    String query = "SELECT * FROM employees ORDER BY salary DESC";
    try (PreparedStatement statement =
        connection.prepareStatement(query, TYPE_SCROLL_SENSITIVE, CONCUR_UPDATABLE)) {
      ResultSet results = statement.executeQuery();
      results.first();
      // user completes lesson if John Smith is the first in the list
      if ((results.getString(2).equals("John")) && (results.getString(3).equals("Smith"))) {
        output.append(SqlInjectionLesson8.generateTable(results));
        return success(this).feedback("sql-injection.9.success").output(output.toString()).build();
      } else {
        return failed(this).feedback("sql-injection.9.one").output(output.toString()).build();
      }
    } catch (SQLException e) {
      return failed(this)
          .output("<br><span class='feedback-negative'>" + e.getMessage() + "</span>")
          .build();
    }
  }
}
