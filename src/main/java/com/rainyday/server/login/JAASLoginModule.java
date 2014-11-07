package com.rainyday.server.login;

import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.FileAppender;
import org.apache.log4j.Level;

import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.apache.log4j.RollingFileAppender;
import sun.security.provider.MD5;

/**
 * @author semika
 *
 */
public class JAASLoginModule implements LoginModule { 
 
    private static Logger LOGGER = Logger.getLogger(JAASLoginModule.class); 
 
    // initial state
    private Subject subject;
    private CallbackHandler callbackHandler;
    private Map sharedState;
    private Map options;

    // configurable option
    private boolean debug = false;
    
    // the authentication status
    private boolean succeeded = false;
    private boolean commitSucceeded = false;
    
    //user credentials
    private String username = null;
    private char[] password = null;
    
    //user principle
    private JAASUserPrincipal userPrincipal = null;
    private JAASPasswordPrincipal passwordPrincipal = null;
    
    public JAASLoginModule() {
         super();
    }

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        this.subject = subject;
        this.callbackHandler = callbackHandler;
        this.sharedState = sharedState;
        this.options = options;
         
        BasicConfigurator.configure(); // basic log4j configuration
        Logger.getRootLogger().setLevel(Level.INFO);
        FileAppender fileAppender = null;
        try {
            fileAppender
                    = new RollingFileAppender(new PatternLayout("%d{dd-MM-yyyy HH:mm:ss} %C %L %-5p:%m%n"), "file.log");
            LOGGER.addAppender(fileAppender);
        } catch (IOException e) {
            e.printStackTrace();
        }

        LOGGER.info("TEST LOG ENTRY");
        debug = "true".equalsIgnoreCase((String)options.get("debug")); 
    }

    @Override
    public boolean login() throws LoginException {
  
        if (callbackHandler == null){
            throw new LoginException("Error: no CallbackHandler available " +
            "to garner authentication information from the user");
        }
        Callback[] callbacks = new Callback[2];
        callbacks[0] = new NameCallback("username");
        callbacks[1] = new PasswordCallback("password: ", false);
  
        try {
   
            callbackHandler.handle(callbacks);
            username = ((NameCallback)callbacks[0]).getName();
            password = ((PasswordCallback)callbacks[1]).getPassword();

            if (debug) {
                LOGGER.info("Username :" + username);
                LOGGER.info("Password : " + password);
            }
   
            if (username == null || password == null) {
                LOGGER.info("Callback handler does not return login data properly");
                throw new LoginException("Callback handler does not return login data properly"); 
            }
   
            if (isValidUser()) { //validate user.
                succeeded = true;
                return true;
            } 
   
        } catch (IOException e) { 
             e.printStackTrace();
        } catch (UnsupportedCallbackException e) {
             e.printStackTrace();
        }
  
        return false;
    }

    @Override
    public boolean commit() throws LoginException {
        if (succeeded == false) {
            return false;
        } else { 
            userPrincipal = new JAASUserPrincipal(username);
            if (!subject.getPrincipals().contains(userPrincipal)) {
                subject.getPrincipals().add(userPrincipal);
                LOGGER.info("User principal added:" + userPrincipal);
            }
            passwordPrincipal = new JAASPasswordPrincipal(new String(password)); 
            if (!subject.getPrincipals().contains(passwordPrincipal)) {
                subject.getPrincipals().add(passwordPrincipal);
                LOGGER.info("Password principal added: " + passwordPrincipal);
            }
      
            //populate subject with roles.
//            List<String> roles = getRoles();
//            for (String role: roles) {
//                JAASRolePrincipal rolePrincipal = new JAASRolePrincipal(role);
//                if (!subject.getPrincipals().contains(rolePrincipal)) {
//                    subject.getPrincipals().add(rolePrincipal); 
//                    LOGGER.info("Role principal added: " + rolePrincipal);
//                }
//            }
      
            commitSucceeded = true;
      
            LOGGER.info("Login subject were successfully populated with principals"); 
      
            return true;
       }
   }

   @Override
   public boolean abort() throws LoginException {
      if (succeeded == false) {
          return false;
      } else if (succeeded == true && commitSucceeded == false) {
          succeeded = false;
          username = null;
          if (password != null) {
              password = null;
          }
          userPrincipal = null;    
      } else {
          logout();
      }
      return true;
   }

    @Override
    public boolean logout() throws LoginException {
        subject.getPrincipals().remove(userPrincipal);
        succeeded = false;
        succeeded = commitSucceeded;
        username = null;
        if (password != null) {
            for (int i = 0; i < password.length; i++){
                password[i] = ' ';
                password = null;
            }
        }
        userPrincipal = null;
        return true;
   }
 
   private boolean isValidUser() throws LoginException {

      String sql = (String)options.get("userQuery");
      Connection con = null;
      ResultSet rs = null;
      PreparedStatement stmt = null;
  
      try {
          con = getConnection();
          stmt = con.prepareStatement("SELECT * FROM  PATCA.USER1 where LOGIN=?");
          stmt.setString(1, username);
         // final MD5 md = MD5.getInstance();
       //   String encryptepPassword = mDigestUtils.md5Hex(password);
          //stmt.setString(2, new String(password));
   
          rs = stmt.executeQuery();

//          String strPassword = "";
//          for (int x = 0; x < password.length; x++) {
//              strPassword = strPassword + password[x];
//          }
         if (rs.next()) { //User exist with the given user name and password.
       //   if("admin".equals(username) && "pass123".equals(strPassword))
            return true;
          }

       } catch (Exception e) {
           LOGGER.info("Error when loading user from the database " + e);
           e.printStackTrace();
       } finally {
           try {
               rs.close();
           } catch (SQLException e) {
               LOGGER.info("Error when closing result set." + e);
           }
           try {
               stmt.close();
           } catch (SQLException e) {
               LOGGER.info("Error when closing statement." + e);
           }
           try {
               con.close();
           } catch (SQLException e) {
               LOGGER.info("Error when closing connection." + e);
           }
       }
       return false;
   }

 /**
  * Returns list of roles assigned to authenticated user.
  * @return
  */
  private List<String> getRoles() { 
  
      Connection con = null;
      ResultSet rs = null;
      PreparedStatement stmt = null;
  
      List<String> roleList = new ArrayList<String>(); 
  
      try {
          con = getConnection();
          String sql = (String)options.get("roleQuery");
          stmt = con.prepareStatement(sql);
          stmt.setString(1, username);
   
          rs = stmt.executeQuery();
   
          if (rs.next()) { 
              roleList.add(rs.getString("rolename")); 
          }
      } catch (Exception e) {
          LOGGER.info("Error when loading user from the database " + e);
          e.printStackTrace();
      } finally {
           try {
               rs.close();
           } catch (SQLException e) {
               LOGGER.info("Error when closing result set." + e);
           }
           try {
               stmt.close();
           } catch (SQLException e) {
               LOGGER.info("Error when closing statement." + e);
           }
           try {
               con.close();
           } catch (SQLException e) {
               LOGGER.info("Error when closing connection." + e);
           }
       }
       return roleList;
 }
 
 /**
  * Returns JDBC connection
  * @return
  * @throws LoginException
  */
  private Connection getConnection() throws LoginException {
  
      String jdbcUser = (String)options.get("jdbcUser");
      String jdbcPassword = (String)options.get("jdbcPassword");
      String jdbcUrl = (String)options.get("jdbcUrl");
      String jdbcDriver = (String)options.get("jdbcDriver");

      Connection con = null;
      try {
         //loading driver
         Class.forName(jdbcDriver).newInstance();
         con = DriverManager.getConnection (jdbcUrl, jdbcUser, jdbcPassword);
      } 
      catch (Exception e) {
         LOGGER.info("Error when creating database connection" + e);
         e.printStackTrace();
      } finally {
      }
      return con;
   }

}
