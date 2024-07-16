import { useEffect, useState } from 'react';
import axios from 'axios';

const UserList = () => {
  const [users, setUsers] = useState([]);

  useEffect(() => {
    const fetchUsers = async () => {
      try {
        const response = await axios.get('http://localhost:8080/users');
        setUsers(response.data);
      } catch (error) {
        console.error('Error fetching users:', error);
        alert('Failed to fetch users: ' + (error.response?.data || error.message));
      }
    };

    fetchUsers();
  }, []);

  const handleDelete = async (userID) => {
    try {
      await axios.post('http://localhost:8080/delete-user', { user_id: userID });
      alert('User deleted successfully');
      setUsers(users.filter(user => user.id !== userID));
    } catch (error) {
      console.error('Error deleting user:', error);
      alert('Failed to delete user: ' + (error.response?.data || error.message));
    }
  };

  return (
    <div>
      <h2>User List</h2>
      <ul>
        {users.map(user => (
          <li key={user.id}>
            <strong>{user.username}</strong> - {user.email} - {user.role} - {user.company_name}
            <button onClick={() => handleDelete(user.id)}>Delete</button>
          </li>
        ))}
      </ul>
    </div>
  );
};

export default UserList;
