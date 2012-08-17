/*
 * Copyright 2011-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.vertx.mods;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.mindrot.jbcrypt.BCrypt;
import org.vertx.java.busmods.BusModBase;
import org.vertx.java.core.Handler;
import org.vertx.java.core.eventbus.Message;
import org.vertx.java.core.json.JsonObject;

// TODO persist session IDs
// TODO reset password
// TODO email verification
/**
 * Basic Authentication Manager Bus Module<p>
 * Please see the busmods manual for a full description<p>
 *
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class AuthManager extends BusModBase {

  private Handler<Message<JsonObject>> loginHandler;
  private Handler<Message<JsonObject>> logoutHandler;
  private Handler<Message<JsonObject>> authoriseHandler;
  private Handler<Message<JsonObject>> createHandler;
  private Handler<Message<JsonObject>> existsHandler;

  protected final Map<String, String> sessions = new HashMap<>();
  protected final Map<String, LoginInfo> logins = new HashMap<>();

  private static final long DEFAULT_SESSION_TIMEOUT = 30 * 60 * 1000;

  private String address;
  private String userCollection;
  private String persistorAddress;
  private long sessionTimeout;

  private static final class LoginInfo {
    final long timerID;
    final String sessionID;

    private LoginInfo(long timerID, String sessionID) {
      this.timerID = timerID;
      this.sessionID = sessionID;
    }
  }

  /**
   * Start the busmod
   */
  public void start() {
    super.start();

    this.address = getOptionalStringConfig("address", "vertx.basicauthmanager");
    this.userCollection = getOptionalStringConfig("user_collection", "users");
    this.persistorAddress = getOptionalStringConfig("persistor_address", "vertx.mongopersistor");
    Number timeout = config.getNumber("session_timeout");
    if (timeout != null) {
      if (timeout instanceof Long) {
        this.sessionTimeout = (Long)timeout;
      } else if (timeout instanceof Integer) {
        this.sessionTimeout = (Integer)timeout;
      }
    } else {
      this.sessionTimeout = DEFAULT_SESSION_TIMEOUT;
    }

    loginHandler = new Handler<Message<JsonObject>>() {
      public void handle(Message<JsonObject> message) {
        doLogin(message);
      }
    };
    eb.registerHandler(address + ".login", loginHandler);
    logoutHandler = new Handler<Message<JsonObject>>() {
      public void handle(Message<JsonObject> message) {
        doLogout(message);
      }
    };
    eb.registerHandler(address + ".logout", logoutHandler);
    authoriseHandler = new Handler<Message<JsonObject>>() {
      public void handle(Message<JsonObject> message) {
        doAuthorise(message);
      }
    };
    eb.registerHandler(address + ".authorise", authoriseHandler);
    createHandler = new Handler<Message<JsonObject>>() {
      public void handle(Message<JsonObject> message) {
        doCreate(message);
      }
    };
    eb.registerHandler(address + ".create", createHandler);
    existsHandler = new Handler<Message<JsonObject>>() {
      public void handle(Message<JsonObject> message) {
        doExists(message);
      }
    };
    eb.registerHandler(address + ".exists", existsHandler);
  }

  private void doLogin(final Message<JsonObject> message) {

    final String username = getMandatoryString("username", message);
    if (username == null) {
      return;
    }
    final String password = getMandatoryString("password", message);
    if (password == null) {
      return;
    }

    JsonObject findMsg = new JsonObject().putString("action", "findone").putString("collection", userCollection);
    JsonObject matcher = new JsonObject().putString("username", username);
    findMsg.putObject("matcher", matcher);

    eb.send(persistorAddress, findMsg, new Handler<Message<JsonObject>>() {
      public void handle(Message<JsonObject> reply) {

        if (reply.body.getString("status").equals("ok")) {
          JsonObject user = reply.body.getObject("result");
          if (user != null) {

            // Check if password matches
            String hashedPassword = user.getString("password");
            if (!BCrypt.checkpw(password, hashedPassword)) {
              sendStatus("denied", message);
            } else {
              
              String sessionID = createSession(username);
              JsonObject jsonReply = new JsonObject().putString("sessionID", sessionID);
              sendOK(message, jsonReply);
            }
          } else {
            // Not found
            sendStatus("denied", message);
          }
        } else {
          logger.error("Failed to execute login query: " + reply.body.getString("message"));
          sendError(message, "Failed to excecute login");
        }
      }
    });
  }

  private String createSession(final String username) {
    // Check if already logged in, if so logout of the old session
    LoginInfo info = logins.get(username);
    if (info != null) {
      logout(info.sessionID);
    }
 
    // Found
    final String sessionID = UUID.randomUUID().toString();
    long timerID = vertx.setTimer(sessionTimeout, new Handler<Long>() {
      public void handle(Long timerID) {
        sessions.remove(sessionID);
        logins.remove(username);
      }
    });
    sessions.put(sessionID, username);
    logins.put(username, new LoginInfo(timerID, sessionID));
    return sessionID;
  }
  
  protected void doLogout(final Message<JsonObject> message) {
    final String sessionID = getMandatoryString("sessionID", message);
    if (sessionID != null) {
      if (logout(sessionID)) {
        sendOK(message);
      } else {
        super.sendError(message, "Not logged in");
      }
    }
  }

  protected boolean logout(String sessionID) {
    String username = sessions.remove(sessionID);
    if (username != null) {
      LoginInfo info = logins.remove(username);
      vertx.cancelTimer(info.timerID);
      return true;
    } else {
      return false;
    }
  }

  protected void doAuthorise(Message<JsonObject> message) {
    String sessionID = getMandatoryString("sessionID", message);
    if (sessionID == null) {
      return;
    }
    String username = sessions.get(sessionID);

    // In this basic auth manager we don't do any resource specific authorisation
    // The user is always authorised if they are logged in

    if (username != null) {
      JsonObject reply = new JsonObject().putString("username", username);
      sendOK(message, reply);
    } else {
      sendStatus("denied", message);
    }
  }

  protected void doCreate(final Message<JsonObject> message) {
    final String name = getMandatoryString("name", message);
    final String username = getMandatoryString("username", message);
    final String password = getMandatoryString("password", message);
    if (username == null || password == null || name == null) {
      return;
    }
    
    // TODO We depend on DB to prevent duplicates
    String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt());
    JsonObject user = new JsonObject().putString("username", username)
        .putString("password", hashedPassword).putString("name", name);
    JsonObject saveMsg = new JsonObject().putString("action", "save")
        .putString("collection", userCollection).putObject("document", user);
    eb.send(persistorAddress, saveMsg, new Handler<Message<JsonObject>>() {
      @Override
      public void handle(Message<JsonObject> saveReply) {
        if (saveReply.body.getString("status").equals("ok")) {
          String sessionID = createSession(username);
          sendOK(message, new JsonObject().putString("sessionID", sessionID));
        } else {
          logger.error("Failed to execute create query: " + saveReply.body.getString("message"));
          sendError(message, "Failed to excecute create");
        }
      }
    });
  }
  
  protected void doExists(final Message<JsonObject> message) {
    final String username = getMandatoryString("username", message);
    if (username == null) {
      return;
    }
    
    JsonObject findMsg = new JsonObject().putString("action", "findone").putString("collection", userCollection);
    JsonObject matcher = new JsonObject().putString("username", username);
    findMsg.putObject("matcher", matcher);

    eb.send(persistorAddress, findMsg, new Handler<Message<JsonObject>>() {
      public void handle(Message<JsonObject> reply) {
        if (reply.body.getString("status").equals("ok")) {
          JsonObject user = reply.body.getObject("result");
          if (user != null) {
            sendOK(message);
          } else {
            sendStatus("not found", message);
          }
        } else {
          logger.error("Failed to execute exists query: " + reply.body.getString("message"));
          sendError(message, "Failed to execute exists");
        }
      }
    });
  }


}
