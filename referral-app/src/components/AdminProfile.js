import React, { useState, useEffect } from 'react';
import { fetchAdminProfile } from '../api';

const AdminProfile = () => {
  const [users, setUsers] = useState([]);

  useEffect(() => {
    const fetchUsers = async () => {
      try {
        const response = await fetchAdminProfile();
        setUsers(response.data);
      } catch (error) {
        console.error('Error fetching admin profile:', error);
      }
    };

    fetchUsers();
  }, []);

  return (
    <div>
      <h2>Admin Profile</h2>
      <ul>
        {users.map(user => (
          <li key={user.id}>{user.username} ({user.email})</li>
        ))}
      </ul>
    </div>
  );
};

export default AdminProfile;
