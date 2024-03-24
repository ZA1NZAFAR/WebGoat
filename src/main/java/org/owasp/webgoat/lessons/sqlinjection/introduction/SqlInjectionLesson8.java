package org.owasp.webgoat.lessons.sqlinjection.introduction;

import java.sql.*;
import java.text.SimpleDateFormat;
import java.util.Calendar;
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
      "SqlStringInjectionHint.8.1",
      "SqlStringInjectionHint.8.2",
      "SqlStringInjectionHint.8.3",
      "SqlStringInjectionHint.8.4",
      "SqlStringInjectionHint.8.5"
    })
public class SqlInjectionLesson8 extends AssignmentEndpoint {

  private final LessonDataSource dataSource;

  public SqlInjectionLesson8(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack8")
  @ResponseBody
  public AttackResult completed(@RequestParam String name, @RequestParam String auth_tan) {
    return injectableQueryConfidentiality(name, auth_tan);
  }

  protected AttackResult injectableQueryConfidentiality(String name, String auth_tan) {
    StringBuilder output = new StringBuilder();
    String query = "SELECT * FROM employees WHERE last_name = ? AND auth_tan = ?";

    try (Connection connection = dataSource.getConnection()) {
      try (PreparedStatement statement =
          connection.prepareStatement(
              query, ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_UPDATABLE)) {
        statement.setString(1, name);
        statement.setString(2, auth_tan);
        log(connection, query); // Note: logging placeholder query
        ResultSet results = statement.executeQuery();

        if (results.getStatement() != null) {
          if (results.first()) {
            output.append(generateTable(results));
            results.last();

            if (results.getRow() > 1) {
              // more than one record, the user succeeded
              return success(this)
                  .feedback("sql-injection.8.success")
                  .output(output.toString())
                  .build();
            } else {
              // only one record
              return failed(this).feedback("sql-injection.8.one").output(output.toString()).build();
            }

          } else {
            // no results
            return failed(this).feedback("sql-injection.8.no.results").build();
          }
        } else {
          return failed(this).build();
        }
      } catch (SQLException e) {
        return failed(this)
            .output("<br><span class='feedback-negative'>" + e.getMessage() + "</span>")
            .build();
      }

    } catch (Exception e) {
      return failed(this)
          .output("<br><span class='feedback-negative'>" + e.getMessage() + "</span>")
          .build();
    }
  }

  public static String generateTable(ResultSet results) throws SQLException {
    ResultSetMetaData resultsMetaData = results.getMetaData();
    int numColumns = resultsMetaData.getColumnCount();
    results.beforeFirst();
    StringBuilder table = new StringBuilder();
    table.append("<table>");

    if (results.next()) {
      table.append("<tr>");
      for (int i = 1; i < (numColumns + 1); i++) {
        table.append("<th>" + resultsMetaData.getColumnName(i) + "</th>");
      }
      table.append("</tr>");

      results.beforeFirst();
      while (results.next()) {
        table.append("<tr>");
        for (int i = 1; i < (numColumns + 1); i++) {
          table.append("<td>" + results.getString(i) + "</td>");
        }
        table.append("</tr>");
      }

    } else {
      table.append("Query Successful; however no data was returned from this query.");
    }

    table.append("</table>");
    return (table.toString());
  }

  public static void log(Connection connection, String action) {
    // Note: This logging method cannot be parameterized as is, due to its structure. Recommend
    // refactoring for actual use.
    Calendar cal = Calendar.getInstance();
    SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    String time = sdf.format(cal.getTime());

    String logQuery = "INSERT INTO access_log (time, action) VALUES (?, ?)";

    try (PreparedStatement logStatement = connection.prepareStatement(logQuery)) {
      logStatement.setString(1, time);
      logStatement.setString(2, action);
      logStatement.executeUpdate();
    } catch (SQLException e) {
      System.err.println(e.getMessage());
    }
  }
}
