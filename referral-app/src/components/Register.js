import React, { useState } from 'react';
import { registerUser } from '../api';

const Register = () => {
  const initialFormData = {
    email: '',
    username: '',
    password: '',
    role: 'user',
    companyName: ''
  };

  const [formData, setFormData] = useState(initialFormData);
  const [error, setError] = useState('');

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await registerUser(formData);
      alert('Registration successful');
      setFormData(initialFormData); // Reset the form
      setError(''); // Clear any previous errors
    } catch (error) {
      console.error('Error registering user:', error);
      if (error.response && error.response.data.message) {
        setError(error.response.data.message);
      } else {
        setError('Registration failed. Please try again.');
      }
    }
  };

  return (
    <form onSubmit={handleSubmit} className="register-form">
      {error && <p className="error-message">{error}</p>}
      <input
        type="email"
        name="email"
        placeholder="Email"
        value={formData.email}
        onChange={handleChange}
        required
      />
      <input
        name="username"
        placeholder="Username"
        value={formData.username}
        onChange={handleChange}
        required
      />
      <input
        type="password"
        name="password"
        placeholder="Password"
        value={formData.password}
        onChange={handleChange}
        required
      />
      <select
        name="role"
        value={formData.role}
        onChange={handleChange}
        required
      >
        <option value="user">Company User</option>
        <option value="admin">Company Admin</option>
        <option value="platformAdmin">Platform Admin</option>
        <option value="superAdmin">Super Admin</option>
      </select>
      <input
        name="companyName"
        placeholder="Company Name"
        value={formData.companyName}
        onChange={handleChange}
      />
      <button type="submit">Register</button>
    </form>
  );
};

export default Register;
