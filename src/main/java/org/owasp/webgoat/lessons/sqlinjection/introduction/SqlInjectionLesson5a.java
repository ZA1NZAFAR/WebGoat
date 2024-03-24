package org.owasp.webgoat.lessons.sqlinjection.introduction;

import java.sql.*;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(value = {"SqlStringInjectionHint5a1"})
public class SqlInjectionLesson5a extends AssignmentEndpoint {

  private static final String EXPLANATION =
      "<br> Explanation: This injection works, because <span style=\"font-style: italic\">or '1' ="
          + " '1'</span> always evaluates to true. So the injected query basically avoids SQL"
          + " injection by using prepared statements.SELECT * FROM user_data WHERE first_name ="
          + " 'John' and last_name = ? , which prevents SQL injection.";

  private final LessonDataSource dataSource;

  public SqlInjectionLesson5a(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/assignment5a")
  @ResponseBody
  public AttackResult completed(
      @RequestParam String account, @RequestParam String operator, @RequestParam String injection) {
    // Here, we'll directly call injectableQuery with the 'account' parameter only as operator and
    // injection are not used safely.
    return injectableQuery(account);
  }

  protected AttackResult injectableQuery(String accountName) {
    String query = "SELECT * FROM user_data WHERE first_name = 'John' and last_name = ?";
    try (Connection connection = dataSource.getConnection();
        PreparedStatement preparedStatement =
            connection.prepareStatement(
                query, ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_UPDATABLE)) {
      preparedStatement.setString(1, accountName);
      try (ResultSet results = preparedStatement.executeQuery()) {

        if ((results != null) && (results.first())) {
          ResultSetMetaData resultsMetaData = results.getMetaData();
          StringBuilder output = new StringBuilder();

          output.append(writeTable(results, resultsMetaData));
          results.last();

          // If they get back more than one user they succeeded
          if (results.getRow() >= 6) {
            return success(this)
                .feedback("sql-injection.5a.success")
                .output("Your query was safely executed with no SQL injection risk" + EXPLANATION)
                .feedbackArgs(output.toString())
                .build();
          } else {
            return failed(this)
                .output(
                    output.toString()
                        + "<br> Your query was safely executed with no SQL injection risk")
                .build();
          }
        } else {
          return failed(this)
              .feedback("sql-injection.5a.no.results")
              .output("Your query was safely executed with no SQL injection risk")
              .build();
        }
      } catch (SQLException sqle) {
        return failed(this)
            .output(
                sqle.getMessage()
                    + "<br> Your query was attempted to be executed safely but encountered an"
                    + " error")
            .build();
      }
    } catch (Exception e) {
      return failed(this)
          .output(
              this.getClass().getName()
                  + " : "
                  + e.getMessage()
                  + "<br> Your query was attempted to be executed safely but encountered an error")
          .build();
    }
  }

  public static String writeTable(ResultSet results, ResultSetMetaData resultsMetaData)
      throws SQLException {
    int numColumns = resultsMetaData.getColumnCount();
    results.beforeFirst();
    StringBuilder t = new StringBuilder();
    t.append("<p>");

    if (results.next()) {
      for (int i = 1; i <= numColumns; i++) {
        t.append(resultsMetaData.getColumnName(i));
        t.append(", ");
      }

      t.append("<br />");
      results.beforeFirst();

      while (results.next()) {

        for (int i = 1; i <= numColumns; i++) {
          t.append(results.getString(i));
          t.append(", ");
        }

        t.append("<br />");
      }
    } else {
      t.append("Query Successful; however, no data was returned from this query.");
    }

    t.append("</p>");
    return (t.toString());
  }
}
