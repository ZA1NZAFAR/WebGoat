package org.owasp.webgoat.lessons.sqlinjection.advanced;

import java.sql.*;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.sqlinjection.introduction.SqlInjectionLesson5a;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(
    value = {
      "SqlStringInjectionHint-advanced-6a-1",
      "SqlStringInjectionHint-advanced-6a-2",
      "SqlStringInjectionHint-advanced-6a-3",
      "SqlStringInjectionHint-advanced-6a-4",
      "SqlStringInjectionHint-advanced-6a-5"
    })
public class SqlInjectionLesson6a extends AssignmentEndpoint {

  private final LessonDataSource dataSource;
  private static final String YOUR_QUERY_WAS = "<br> Your query was: ";

  public SqlInjectionLesson6a(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjectionAdvanced/attack6a")
  @ResponseBody
  public AttackResult completed(@RequestParam(value = "userid_6a") String userId) {
    return injectableQuery(userId);
  }

  public AttackResult injectableQuery(String accountName) {
    String query = "SELECT * FROM user_data WHERE last_name = ?";
    try (Connection connection = dataSource.getConnection()) {
      boolean usedUnion = accountName.toLowerCase().contains("union");
      try (PreparedStatement preparedStatement =
          connection.prepareStatement(
              query, ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY)) {
        preparedStatement.setString(1, accountName);
        ResultSet results = preparedStatement.executeQuery();

        if (results.first()) {
          ResultSetMetaData resultsMetaData = results.getMetaData();
          StringBuilder output = new StringBuilder();

          output.append(SqlInjectionLesson5a.writeTable(results, resultsMetaData));

          String appendingWhenSucceded =
              usedUnion
                  ? "Well done! Can you also figure out a solution, by appending a new SQL"
                      + " Statement?"
                  : "Well done! Can you also figure out a solution, by using a UNION?";

          results.last();

          if (output.toString().contains("dave") && output.toString().contains("passW0rD")) {
            output.append(appendingWhenSucceded);
            return success(this)
                .feedback("sql-injection.advanced.6a.success")
                .feedbackArgs(output.toString())
                .output(YOUR_QUERY_WAS + query)
                .build();
          } else {
            return failed(this)
                .output(output.toString() + YOUR_QUERY_WAS + preparedStatement.toString())
                .build();
          }
        } else {
          return failed(this)
              .feedback("sql-injection.advanced.6a.no.results")
              .output(YOUR_QUERY_WAS + preparedStatement.toString())
              .build();
        }
      } catch (SQLException sqle) {
        return failed(this).output(sqle.getMessage() + YOUR_QUERY_WAS + query).build();
      }
    } catch (Exception e) {
      return failed(this)
          .output(this.getClass().getName() + " : " + e.getMessage() + YOUR_QUERY_WAS + query)
          .build();
    }
  }
}
