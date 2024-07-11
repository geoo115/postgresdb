import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { registerUser } from '../api'; 

const Register = () => {
  const [userData, setUserData] = useState({
    email: '',
    username: '',
    password: '',
    role: 'user', // Default value
    company_name: '',
  });
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const navigate = useNavigate();

  const handleChange = (e) => {
    const { name, value } = e.target;
    setUserData((prevData) => ({
      ...prevData,
      [name]: value,
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    try {
      const response = await registerUser(userData);
      setSuccess('User registered successfully');
      console.log('Registration response:', response);
      // Redirect to login page or another appropriate page after successful registration
      navigate('/login');
    } catch (error) {
      console.error('Error registering user:', error);
      setError(error.message || 'Registration failed. Please try again.');
    }
  };

  return (
    <div>
      <h2>Register</h2>
      {error && <div style={{ color: 'red' }}>{error}</div>}
      {success && <div style={{ color: 'green' }}>{success}</div>}
      <form onSubmit={handleSubmit}>
        <div>
          <label>Email:</label>
          <input
            type="email"
            name="email"
            value={userData.email}
            onChange={handleChange}
            required
          />
        </div>
        <div>
          <label>Username:</label>
          <input
            type="text"
            name="username"
            value={userData.username}
            onChange={handleChange}
            required
          />
        </div>
        <div>
          <label>Password:</label>
          <input
            type="password"
            name="password"
            value={userData.password}
            onChange={handleChange}
            required
          />
        </div>
        <div>
          <label>Role:</label>
          <select
            name="role"
            value={userData.role}
            onChange={handleChange}
            required
          >
            <option value="user">Company User</option>
            <option value="admin">Company Admin</option>
            <option value="platformAdmin">Platform Admin</option>
            <option value="superAdmin">Super Admin</option>
          </select>
        </div>
        <div>
          <label>Company Name:</label>
          <input
            type="text"
            name="company_name"
            value={userData.company_name}
            onChange={handleChange}
            required
          />
        </div>
        <button type="submit">Register</button>
      </form>
    </div>
  );
};

export default Register;
