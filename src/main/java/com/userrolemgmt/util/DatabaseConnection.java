package com.userrolemgmt.util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.Level;
import java.util.logging.Logger;

public class DatabaseConnection {
    private static final Logger LOGGER = Logger.getLogger(DatabaseConnection.class.getName());
    private static DatabaseConnection instance;
    private Connection connection;

    private DatabaseConnection() {
        try {
            // Load Oracle JDBC Driver
            Class.forName("oracle.jdbc.driver.OracleDriver");
            LOGGER.log(Level.INFO, "Oracle JDBC Driver loaded successfully");

            // Create a temporary directory for the wallet
            File tempDir = Files.createTempDirectory("oracle_wallet").toFile();
            tempDir.deleteOnExit(); // Ensure it gets deleted on exit

            // Copy wallet files to the temporary directory
            copyWalletFiles(tempDir);

            // Set wallet location
            // String walletPath = tempDir.getAbsolutePath();
            // String user = "DCN2_DB";
            // String password = "8xeZzy-jokgew";
            // String url =
            // "jdbc:oracle:thin:@(description=(address=(protocol=tcps)(port=1522)(host=adb.sa-santiago-1.oraclecloud.com))(connect_data=(service_name=g5775c4e4540b4a_swzaddavly6hv92c_high.adb.oraclecloud.com))(security=(wallet_location="
            // + walletPath + ")))";

            String walletPath = tempDir.getAbsolutePath().replace("\\", "/");
            // Obtener valores de variables de entorno
            String user = System.getenv("ORACLE_USER");
            String password = System.getenv("ORACLE_PASSWORD");
            String tnsName = System.getenv("ORACLE_TNS_NAME");

            String serviceName = System.getenv("ORACLE_SERVICE_NAME");

            // Validar que las variables estén configuradas
            if (user == null || password == null || tnsName == null) {
                throw new RuntimeException(
                        "Faltan variables de entorno: ORACLE_USER, ORACLE_PASSWORD, ORACLE_TNS_NAME");
            }
            // Construir URL usando el TNS name
            String url = String.format(
                    "jdbc:oracle:thin:@(description=(address=(protocol=tcps)(port=1522)(host=adb.sa-santiago-1.oraclecloud.com))(connect_data=(service_name=%s))(security=(wallet_location=%s)))",
                    serviceName,
                    walletPath);

            LOGGER.log(Level.INFO, "Connecting to Oracle Autonomous Database with URL: " + url);
            connection = DriverManager.getConnection(url, user, password);
            LOGGER.log(Level.INFO, "Connection to Oracle DB established successfully");

            initializeDatabase();

        } catch (ClassNotFoundException e) {
            LOGGER.log(Level.SEVERE, "Oracle JDBC Driver not found", e);
            throw new RuntimeException("Oracle JDBC Driver not found", e);
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error connecting to Oracle Database", e);
            throw new RuntimeException("Connection error to Oracle DB", e);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error setting up wallet files", e);
            throw new RuntimeException("Error setting up wallet files", e);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "General error", e);
            throw new RuntimeException("General error: " + e.getMessage(), e);
        }
    }

    private void copyWalletFiles(File destinationDir) throws IOException {
        // Copy each wallet file from the resources folder to the temporary directory
        String[] walletFiles = { "cwallet.sso", "ewallet.p12", "keystore.jks", "tnsnames.ora" }; // Add any other wallet
                                                                                                 // files you need

        for (String fileName : walletFiles) {
            try (InputStream in = getClass().getClassLoader().getResourceAsStream("wallet/" + fileName)) {
                if (in == null) {
                    throw new IOException("Wallet file not found in resources: " + fileName);
                }
                File outFile = new File(destinationDir, fileName);
                try (FileOutputStream out = new FileOutputStream(outFile)) {
                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = in.read(buffer)) != -1) {
                        out.write(buffer, 0, bytesRead);
                    }
                }
            }
        }
    }

    private void initializeDatabase() {
        try {
            LOGGER.log(Level.INFO, "Initializing database schema");

            try (Statement stmt = connection.createStatement()) {
                // Check and create users table if it doesn't exist
                String createUsersTable = "BEGIN "
                        + "  EXECUTE IMMEDIATE 'CREATE TABLE users (" +
                        "user_id NUMBER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, " +
                        "username VARCHAR2(100) NOT NULL, " +
                        "email VARCHAR2(255) NOT NULL, " +
                        "password_hash VARCHAR2(255) NOT NULL, " +
                        "first_name VARCHAR2(100), " +
                        "last_name VARCHAR2(100), " +
                        "active CHAR(1) DEFAULT ''Y'', " +
                        "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
                        "updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)'; "
                        + "EXCEPTION "
                        + "  WHEN OTHERS THEN "
                        + "    IF SQLCODE != -955 THEN "
                        + "      RAISE; "
                        + "    END IF; "
                        + "END;";
                stmt.execute(createUsersTable);

                // Check and create roles table if it doesn't exist
                String createRolesTable = "BEGIN "
                        + "  EXECUTE IMMEDIATE 'CREATE TABLE roles (" +
                        "role_id NUMBER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, " +
                        "role_name VARCHAR2(100) NOT NULL, " +
                        "description VARCHAR2(255), " +
                        "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
                        "updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)'; "
                        + "EXCEPTION "
                        + "  WHEN OTHERS THEN "
                        + "    IF SQLCODE != -955 THEN "
                        + "      RAISE; "
                        + "    END IF; "
                        + "END;";
                stmt.execute(createRolesTable);

                // Check and create user_roles table if it doesn't exist
                String createUserRolesTable = "BEGIN "
                        + "  EXECUTE IMMEDIATE 'CREATE TABLE user_roles (" +
                        "user_id NUMBER NOT NULL, " +
                        "role_id NUMBER NOT NULL, " +
                        "assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
                        "PRIMARY KEY (user_id, role_id), " +
                        "FOREIGN KEY (user_id) REFERENCES users(user_id), " +
                        "FOREIGN KEY (role_id) REFERENCES roles(role_id))'; "
                        + "EXCEPTION "
                        + "  WHEN OTHERS THEN "
                        + "    IF SQLCODE != -955 THEN "
                        + "      RAISE; "
                        + "    END IF; "
                        + "END;";
                stmt.execute(createUserRolesTable);

                // Insert example data (only if no data exists)
                LOGGER.log(Level.INFO, "Inserting example data");

                // Users example
                stmt.execute("INSERT INTO users (username, email, password_hash, first_name, last_name) "
                        + "SELECT 'admin', 'admin@example.com', 'hashed_password', 'Admin', 'User' FROM DUAL "
                        + "WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = 'admin')");

                stmt.execute("INSERT INTO users (username, email, password_hash, first_name, last_name) "
                        + "SELECT 'user1', 'user1@example.com', 'hashed_password', 'Regular', 'User' FROM DUAL "
                        + "WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = 'user1')");

                stmt.execute("INSERT INTO users (username, email, password_hash, first_name, last_name) "
                        + "SELECT 'manager', 'manager@example.com', 'hashed_password', 'Manager', 'User' FROM DUAL "
                        + "WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = 'manager')");

                // Roles example
                stmt.execute("INSERT INTO roles (role_name, description) "
                        + "SELECT 'ADMIN', 'Administrator role with full access' FROM DUAL "
                        + "WHERE NOT EXISTS (SELECT 1 FROM roles WHERE role_name = 'ADMIN')");

                stmt.execute("INSERT INTO roles (role_name, description) "
                        + "SELECT 'USER', 'Regular user with limited access' FROM DUAL "
                        + "WHERE NOT EXISTS (SELECT 1 FROM roles WHERE role_name = 'USER')");

                stmt.execute("INSERT INTO roles (role_name, description) "
                        + "SELECT 'MANAGER', 'Manager with department access' FROM DUAL "
                        + "WHERE NOT EXISTS (SELECT 1 FROM roles WHERE role_name = 'MANAGER')");

                // User-role assignments
                stmt.execute("INSERT INTO user_roles (user_id, role_id) "
                        + "SELECT u.user_id, r.role_id FROM users u, roles r "
                        + "WHERE u.username = 'admin' AND r.role_name = 'ADMIN' "
                        + "AND NOT EXISTS (SELECT 1 FROM user_roles ur WHERE ur.user_id = u.user_id AND ur.role_id = r.role_id)");

                stmt.execute("INSERT INTO user_roles (user_id, role_id) "
                        + "SELECT u.user_id, r.role_id FROM users u, roles r "
                        + "WHERE u.username = 'user1' AND r.role_name = 'USER' "
                        + "AND NOT EXISTS (SELECT 1 FROM user_roles ur WHERE ur.user_id = u.user_id AND ur.role_id = r.role_id)");

                stmt.execute("INSERT INTO user_roles (user_id, role_id) "
                        + "SELECT u.user_id, r.role_id FROM users u, roles r "
                        + "WHERE u.username = 'manager' AND r.role_name = 'MANAGER' "
                        + "AND NOT EXISTS (SELECT 1 FROM user_roles ur WHERE ur.user_id = u.user_id AND ur.role_id = r.role_id)");

            }

            LOGGER.log(Level.INFO, "Database initialized successfully");

        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error initializing the database", e);
            throw new RuntimeException("Error initializing the database", e);
        }
    }

    public static synchronized DatabaseConnection getInstance() {
        if (instance == null) {
            instance = new DatabaseConnection();
        }
        return instance;
    }

    public Connection getConnection() {
        try {
            if (connection == null || connection.isClosed()) {
                instance = new DatabaseConnection();
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error verifying connection status", e);
            throw new RuntimeException("Error verifying connection", e);
        }
        return connection;
    }

    public void closeConnection() {
        if (connection != null) {
            try {
                connection.close();
                LOGGER.log(Level.INFO, "Connection closed successfully");
            } catch (SQLException e) {
                LOGGER.log(Level.WARNING, "Error closing connection", e);
            }
        }
    }
}
