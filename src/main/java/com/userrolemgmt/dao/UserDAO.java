package com.userrolemgmt.dao;

import com.userrolemgmt.model.Role;
import com.userrolemgmt.model.User;
import com.userrolemgmt.util.DatabaseConnection;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class UserDAO {
    private static final Logger LOGGER = Logger.getLogger(UserDAO.class.getName());
    private final Connection connection;

    public UserDAO() {
        this.connection = DatabaseConnection.getInstance().getConnection();
    }

    // Obtener todos los usuarios
    public List<User> getAllUsers() throws SQLException {
        List<User> users = new ArrayList<>();
        String query = "SELECT * FROM users ORDER BY user_id";

        try (Statement stmt = connection.createStatement();
                ResultSet rs = stmt.executeQuery(query)) {

            while (rs.next()) {
                User user = mapResultSetToUser(rs);
                // Cargar roles para este usuario
                user.setRoles(getUserRoles(user.getUserId()));
                users.add(user);
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error al obtener todos los usuarios", e);
            throw e;
        }

        return users;
    }

    // Obtener un usuario por ID
    public User getUserById(long userId) throws SQLException {
        String query = "SELECT * FROM users WHERE user_id = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(query)) {
            pstmt.setLong(1, userId);

            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    User user = mapResultSetToUser(rs);
                    // Cargar roles para este usuario
                    user.setRoles(getUserRoles(userId));
                    return user;
                }
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error al obtener usuario por ID: " + userId, e);
            throw e;
        }

        return null;
    }

    // Obtener un usuario por nombre de usuario
    public User getUserByUsername(String username) throws SQLException {
        String query = "SELECT * FROM users WHERE username = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(query)) {
            pstmt.setString(1, username);

            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    User user = mapResultSetToUser(rs);
                    // Cargar roles para este usuario
                    user.setRoles(getUserRoles(user.getUserId()));
                    return user;
                }
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error al obtener usuario por username: " + username, e);
            throw e;
        }

        return null;
    }

    // Crear un nuevo usuario
    public User createUser(User user) throws SQLException {
        // Enfoque Oracle mejorado
        String oracleQuery = "BEGIN " +
                "  INSERT INTO users (username, email, password_hash, first_name, last_name, active) " +
                "  VALUES (?, ?, ?, ?, ?, ?) " +
                "  RETURNING user_id, created_at, updated_at INTO ?, ?, ?; " +
                "END;";

        try (CallableStatement cstmt = connection.prepareCall(oracleQuery)) {
            // Parámetros de entrada
            cstmt.setString(1, user.getUsername());
            cstmt.setString(2, user.getEmail());
            cstmt.setString(3, user.getPasswordHash());
            cstmt.setString(4, user.getFirstName());
            cstmt.setString(5, user.getLastName());
            cstmt.setString(6, user.isActive() ? "Y" : "N"); // Usar String para CHAR(1)

            // Registrar parámetros de salida
            cstmt.registerOutParameter(7, Types.NUMERIC); // user_id
            cstmt.registerOutParameter(8, Types.TIMESTAMP); // created_at
            cstmt.registerOutParameter(9, Types.TIMESTAMP); // updated_at

            cstmt.execute();

            // Obtener valores devueltos
            user.setUserId(cstmt.getLong(7));
            user.setCreatedAt(cstmt.getTimestamp(8));
            user.setUpdatedAt(cstmt.getTimestamp(9));

            // Asignar roles
            if (user.getRoles() != null && !user.getRoles().isEmpty()) {
                for (Role role : user.getRoles()) {
                    assignRoleToUser(user.getUserId(), role.getRoleId());
                }
                user.setRoles(getUserRoles(user.getUserId()));
            }

            return user;

        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error al crear usuario", e);
            throw e;
        }
    }

    // Actualizar un usuario existente
    public boolean updateUser(User user) throws SQLException {
        String query = "UPDATE users SET username = ?, email = ?, password_hash = ?, " +
                "first_name = ?, last_name = ?, active = ? " +
                "WHERE user_id = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(query)) {
            pstmt.setString(1, user.getUsername());
            pstmt.setString(2, user.getEmail());
            pstmt.setString(3, user.getPasswordHash());
            pstmt.setString(4, user.getFirstName());
            pstmt.setString(5, user.getLastName());
            pstmt.setString(6, user.isActive() ? "Y" : "N"); // Usar "Y"/"N" en lugar de 1/0
            pstmt.setLong(7, user.getUserId());

            int rowsAffected = pstmt.executeUpdate();

            // Actualizar roles si es necesario
            if (rowsAffected > 0 && user.getRoles() != null) {
                // Eliminar todos los roles actuales
                removeAllRolesFromUser(user.getUserId());

                // Asignar nuevos roles
                for (Role role : user.getRoles()) {
                    assignRoleToUser(user.getUserId(), role.getRoleId());
                }
            }

            return rowsAffected > 0;
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error al actualizar usuario ID: " + user.getUserId(), e);
            throw e;
        }
    }

    // Eliminar un usuario
    public boolean deleteUser(long userId) throws SQLException {
        // Primero eliminar relaciones en user_roles
        removeAllRolesFromUser(userId);

        // Luego eliminar el usuario
        String query = "DELETE FROM users WHERE user_id = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(query)) {
            pstmt.setLong(1, userId);

            int rowsAffected = pstmt.executeUpdate();
            return rowsAffected > 0;
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error al eliminar usuario ID: " + userId, e);
            throw e;
        }
    }

    // Asignar un rol a un usuario
    public boolean assignRoleToUser(long userId, long roleId) throws SQLException {
        String query = "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)";

        try (PreparedStatement pstmt = connection.prepareStatement(query)) {
            pstmt.setLong(1, userId);
            pstmt.setLong(2, roleId);

            int rowsAffected = pstmt.executeUpdate();
            return rowsAffected > 0;
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error al asignar rol ID: " + roleId + " a usuario ID: " + userId, e);
            throw e;
        }
    }

    // Eliminar un rol de un usuario
    public boolean removeRoleFromUser(long userId, long roleId) throws SQLException {
        String query = "DELETE FROM user_roles WHERE user_id = ? AND role_id = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(query)) {
            pstmt.setLong(1, userId);
            pstmt.setLong(2, roleId);

            int rowsAffected = pstmt.executeUpdate();
            return rowsAffected > 0;
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error al eliminar rol ID: " + roleId + " de usuario ID: " + userId, e);
            throw e;
        }
    }

    // Eliminar todos los roles de un usuario
    private boolean removeAllRolesFromUser(long userId) throws SQLException {
        String query = "DELETE FROM user_roles WHERE user_id = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(query)) {
            pstmt.setLong(1, userId);

            int rowsAffected = pstmt.executeUpdate();
            return true;
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error al eliminar todos los roles del usuario ID: " + userId, e);
            throw e;
        }
    }

    // Obtener roles de un usuario
    private List<Role> getUserRoles(long userId) throws SQLException {
        List<Role> roles = new ArrayList<>();
        String query = "SELECT r.* FROM roles r " +
                "JOIN user_roles ur ON r.role_id = ur.role_id " +
                "WHERE ur.user_id = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(query)) {
            pstmt.setLong(1, userId);

            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    Role role = new Role(
                            rs.getLong("role_id"),
                            rs.getString("role_name"),
                            rs.getString("description"),
                            rs.getTimestamp("created_at"),
                            rs.getTimestamp("updated_at"));
                    roles.add(role);
                }
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error al obtener roles del usuario ID: " + userId, e);
            throw e;
        }

        return roles;
    }

    // Método auxiliar para mapear ResultSet a objeto User
    // private User mapResultSetToUser(ResultSet rs) throws SQLException {
    // return new User(
    // rs.getLong("user_id"),
    // rs.getString("username"),
    // rs.getString("email"),
    // rs.getString("password_hash"),
    // rs.getString("first_name"),
    // rs.getString("last_name"),
    // rs.getInt("active") == 1,
    // rs.getTimestamp("created_at"),
    // rs.getTimestamp("updated_at"));
    // }
    private User mapResultSetToUser(ResultSet rs) throws SQLException {
        // Safely handle nullable fields (e.g., first_name, last_name, email)
        String firstName = rs.getString("first_name");
        String lastName = rs.getString("last_name");
        String email = rs.getString("email");

        // Handle the active field as a CHAR(1) (e.g., 'Y' or 'N')
        String activeString = rs.getString("active");
        boolean isActive = "Y".equalsIgnoreCase(activeString); // Correcto

        // Handle possible null values for timestamps
        java.sql.Timestamp createdAt = rs.getTimestamp("created_at");
        java.sql.Timestamp updatedAt = rs.getTimestamp("updated_at");

        // Return a User object with safe mappings
        return new User(
                rs.getLong("user_id"), // Assuming user_id is never null
                rs.getString("username"), // Assuming username is never null
                email, // Nullable field
                rs.getString("password_hash"),
                firstName, // Nullable field
                lastName, // Nullable field
                isActive, // Active flag, default to false if 'N' or null
                createdAt, // Nullable timestamp
                updatedAt // Nullable timestamp
        );
    }
}