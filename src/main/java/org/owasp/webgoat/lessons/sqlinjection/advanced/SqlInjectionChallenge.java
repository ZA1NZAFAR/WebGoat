package org.owasp.webgoat.lessons.sqlinjection.advanced;

import java.sql.*;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(
    value = {"SqlInjectionChallenge1", "SqlInjectionChallenge2", "SqlInjectionChallenge3"})
@Slf4j
public class SqlInjectionChallenge extends AssignmentEndpoint {

  private final LessonDataSource dataSource;

  public SqlInjectionChallenge(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PutMapping("/SqlInjectionAdvanced/challenge")
  @ResponseBody
  public AttackResult registerNewUser(
      @RequestParam String username_reg,
      @RequestParam String email_reg,
      @RequestParam String password_reg)
      throws Exception {
    AttackResult attackResult = checkArguments(username_reg, email_reg, password_reg);

    if (attackResult == null) {
      try (Connection connection = dataSource.getConnection()) {
        // Fixed to use a PreparedStatement to prevent SQL injection
        String checkUserQuery = "SELECT userid FROM sql_challenge_users WHERE userid = ?";
        PreparedStatement checkUserStmt = connection.prepareStatement(checkUserQuery);
        checkUserStmt.setString(1, username_reg);
        ResultSet resultSet = checkUserStmt.executeQuery();

        if (resultSet.next()) {
          if (username_reg.contains("tom'")) {
            attackResult = success(this).feedback("user.exists").build();
          } else {
            attackResult = failed(this).feedback("user.exists").feedbackArgs(username_reg).build();
          }
        } else {
          PreparedStatement preparedStatement =
              connection.prepareStatement("INSERT INTO sql_challenge_users VALUES (?, ?, ?)");
          preparedStatement.setString(1, username_reg);
          preparedStatement.setString(2, email_reg);
          preparedStatement.setString(3, password_reg);
          preparedStatement.execute();
          attackResult = success(this).feedback("user.created").feedbackArgs(username_reg).build();
        }
      } catch (SQLException e) {
        attackResult = failed(this).output("Something went wrong").build();
      }
    }
    return attackResult;
  }

  private AttackResult checkArguments(String username_reg, String email_reg, String password_reg) {
    if (StringUtils.isEmpty(username_reg)
        || StringUtils.isEmpty(email_reg)
        || StringUtils.isEmpty(password_reg)) {
      return failed(this).feedback("input.invalid").build();
    }
    if (username_reg.length() > 250 || email_reg.length() > 30 || password_reg.length() > 30) {
      return failed(this).feedback("input.invalid").build();
    }
    return null;
  }
}
