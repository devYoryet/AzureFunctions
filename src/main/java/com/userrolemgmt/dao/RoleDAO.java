package com.userrolemgmt.dao;

import com.userrolemgmt.model.Role;
import com.userrolemgmt.model.User;
import com.userrolemgmt.util.DatabaseConnection;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class RoleDAO {
    private static final Logger LOGGER = Logger.getLogger(RoleDAO.class.getName());
    private final Connection connection;

    public RoleDAO() {
        this.connection = DatabaseConnection.getInstance().getConnection();
    }

    // Obtener todos los roles
    public List<Role> getAllRoles() throws SQLException {
        List<Role> roles = new ArrayList<>();
        String query = "SELECT * FROM roles ORDER BY role_id";

        try (Statement stmt = connection.createStatement();
                ResultSet rs = stmt.executeQuery(query)) {

            while (rs.next()) {
                roles.add(mapResultSetToRole(rs));
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error al obtener todos los roles", e);
            throw e;
        }

        return roles;
    }

    // Obtener un rol por ID
    public Role getRoleById(long roleId) throws SQLException {
        String query = "SELECT * FROM roles WHERE role_id = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(query)) {
            pstmt.setLong(1, roleId);

            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return mapResultSetToRole(rs);
                }
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error al obtener rol por ID: " + roleId, e);
            throw e;
        }

        return null;
    }

    // Obtener un rol por nombre
    public Role getRoleByName(String roleName) throws SQLException {
        String query = "SELECT * FROM roles WHERE role_name = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(query)) {
            pstmt.setString(1, roleName);

            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return mapResultSetToRole(rs);
                }
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error al obtener rol por nombre: " + roleName, e);
            throw e;
        }

        return null;
    }

    // Crear un nuevo rol
    public Role createRole(Role role) throws SQLException {
        // Usar bloque PL/SQL con RETURNING INTO para Oracle
        String oracleQuery = "BEGIN " +
                "  INSERT INTO roles (role_name, description) " +
                "  VALUES (?, ?) " +
                "  RETURNING role_id, created_at, updated_at INTO ?, ?, ?; " +
                "END;";

        try (CallableStatement cstmt = connection.prepareCall(oracleQuery)) {
            // Parámetros de entrada
            cstmt.setString(1, role.getRoleName());
            cstmt.setString(2, role.getDescription());

            // Registrar parámetros de salida
            cstmt.registerOutParameter(3, Types.NUMERIC); // role_id
            cstmt.registerOutParameter(4, Types.TIMESTAMP); // created_at
            cstmt.registerOutParameter(5, Types.TIMESTAMP); // updated_at

            cstmt.execute();

            // Obtener valores devueltos
            role.setRoleId(cstmt.getLong(3));
            role.setCreatedAt(cstmt.getTimestamp(4));
            role.setUpdatedAt(cstmt.getTimestamp(5));

            return role;

        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error al crear rol", e);
            throw e;
        }
    }

    // Actualizar un rol existente
    public boolean updateRole(Role role) throws SQLException {
        String query = "UPDATE roles SET role_name = ?, description = ? WHERE role_id = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(query)) {
            pstmt.setString(1, role.getRoleName());
            pstmt.setString(2, role.getDescription());
            pstmt.setLong(3, role.getRoleId());

            int rowsAffected = pstmt.executeUpdate();
            return rowsAffected > 0;
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error al actualizar rol ID: " + role.getRoleId(), e);
            throw e;
        }
    }

    // Eliminar un rol
    public boolean deleteRole(long roleId) throws SQLException {
        // Primero eliminar todas las referencias en user_roles
        String deleteUserRolesQuery = "DELETE FROM user_roles WHERE role_id = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(deleteUserRolesQuery)) {
            pstmt.setLong(1, roleId);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error al eliminar relaciones de user_roles para rol ID: " + roleId, e);
            throw e;
        }

        // Luego eliminar el rol
        String deleteRoleQuery = "DELETE FROM roles WHERE role_id = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(deleteRoleQuery)) {
            pstmt.setLong(1, roleId);

            int rowsAffected = pstmt.executeUpdate();
            return rowsAffected > 0;
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error al eliminar rol ID: " + roleId, e);
            throw e;
        }
    }

    // Obtener usuarios asignados a un rol
    public List<User> getUsersByRoleId(long roleId) throws SQLException {
        List<User> users = new ArrayList<>();
        String query = "SELECT u.* FROM users u " +
                "JOIN user_roles ur ON u.user_id = ur.user_id " +
                "WHERE ur.role_id = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(query)) {
            pstmt.setLong(1, roleId);

            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    User user = new User(
                            rs.getLong("user_id"),
                            rs.getString("username"),
                            rs.getString("email"),
                            rs.getString("password_hash"),
                            rs.getString("first_name"),
                            rs.getString("last_name"),
                            rs.getInt("active") == 1,
                            rs.getTimestamp("created_at"),
                            rs.getTimestamp("updated_at"));
                    users.add(user);
                }
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error al obtener usuarios para rol ID: " + roleId, e);
            throw e;
        }

        return users;
    }

    // Método auxiliar para mapear ResultSet a objeto Role
    private Role mapResultSetToRole(ResultSet rs) throws SQLException {
        return new Role(
                rs.getLong("role_id"),
                rs.getString("role_name"),
                rs.getString("description"),
                rs.getTimestamp("created_at"),
                rs.getTimestamp("updated_at"));
    }
}