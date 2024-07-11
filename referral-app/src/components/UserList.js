import React, { useState } from 'react';
import { updateUser, deleteUser } from '../api';

const UserList = ({ users, refreshData }) => {
  const [updateUserData, setUpdateUserData] = useState({});

  console.log(users); // Add this line to inspect the users array

  const handleDeleteUser = async (userId) => {
    try {
      await deleteUser(userId);
      refreshData();
    } catch (error) {
      console.error('Error deleting user:', error);
    }
  };

  const handleUpdateUser = async (e, userId) => {
    e.preventDefault();
    try {
      await updateUser(userId, updateUserData[userId]);
      setUpdateUserData((prev) => {
        const newState = { ...prev };
        delete newState[userId]; // Clear updateUserData after successful update
        return newState;
      });
      refreshData(); // Refresh user data after update
    } catch (error) {
      console.error('Error updating user:', error);
    }
  };

  return (
    <section>
      <h2>Existing Users</h2>
      {users.length > 0 ? (
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Email</th>
              <th>Username</th>
              <th>Role</th>
              <th>Company ID</th>
              <th>Company Name</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {users.map(user => (
              <tr key={user.id}>
                <td>{user.id}</td>
                <td>{user.email}</td>
                <td>{user.username}</td>
                <td>{user.role}</td>
                <td>{user.company_id}</td>
                <td>{user.company_name}</td>
                <td>
                  <button onClick={() => handleDeleteUser(user.id)}>Delete</button>
                  <button onClick={() => setUpdateUserData((prev) => ({ ...prev, [user.id]: user }))}>
                    Update
                  </button>
                  {updateUserData[user.id] && (
                    <form onSubmit={(e) => handleUpdateUser(e, user.id)}>
                      <label htmlFor={`email-${user.id}`}>Email:</label>
                      <input
                        type="email"
                        id={`email-${user.id}`}
                        name="email"
                        value={updateUserData[user.id].email}
                        onChange={(e) =>
                          setUpdateUserData((prev) => ({
                            ...prev,
                            [user.id]: { ...prev[user.id], email: e.target.value },
                          }))
                        }
                        required
                      />
                      <br />
                      <label htmlFor={`username-${user.id}`}>Username:</label>
                      <input
                        type="text"
                        id={`username-${user.id}`}
                        name="username"
                        value={updateUserData[user.id].username}
                        onChange={(e) =>
                          setUpdateUserData((prev) => ({
                            ...prev,
                            [user.id]: { ...prev[user.id], username: e.target.value },
                          }))
                        }
                        required
                      />
                      <br />
                      {/* Enhance security: add password reset with proper security */}
                      <label htmlFor={`password-${user.id}`}>Password:</label>
                      <input
                        type="password"
                        id={`password-${user.id}`}
                        name="password"
                        placeholder="Enter new password"
                        onChange={(e) =>
                          setUpdateUserData((prev) => ({
                            ...prev,
                            [user.id]: { ...prev[user.id], password: e.target.value },
                          }))
                        }
                        required
                      />
                      <br />
                      <label htmlFor={`role-${user.id}`}>Role:</label>
                      <select
                        id={`role-${user.id}`}
                        name="role"
                        value={updateUserData[user.id].role}
                        onChange={(e) =>
                          setUpdateUserData((prev) => ({
                            ...prev,
                            [user.id]: { ...prev[user.id], role: e.target.value },
                          }))
                        }
                        required
                      >
                        <option value="platformAdmin">Platform Admin</option>
                        <option value="companyAdmin">Company Admin</option>
                        <option value="user">Standard User</option>
                      </select>
                      <br />
                      <label htmlFor={`company-${user.id}`}>Company ID:</label>
                      <input
                        id={`company-${user.id}`}
                        name="company_id"
                        value={updateUserData[user.id].company_id}
                        onChange={(e) =>
                          setUpdateUserData((prev) => ({
                            ...prev,
                            [user.id]: { ...prev[user.id], company_id: e.target.value },
                          }))
                        }
                        required
                      />
                      <br />
                      <label htmlFor={`company-name-${user.id}`}>Company Name:</label>
                      <input
                        id={`company-name-${user.id}`}
                        name="company_name"
                        value={updateUserData[user.id].company_name}
                        onChange={(e) =>
                          setUpdateUserData((prev) => ({
                            ...prev,
                            [user.id]: { ...prev[user.id], company_name: e.target.value },
                          }))
                        }
                        required
                      />
                      <br />
                      <button type="submit">Save Changes</button>
                    </form>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p>No users found.</p>
      )}
    </section>
  );
};

export default UserList;
