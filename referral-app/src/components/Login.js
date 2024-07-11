import React, { useState } from 'react';
import { loginUser } from '../api';
import user_icon from "../assets/person.png";
import password_icon from "../assets/password.png";
import '../styles/Login.css';


const Login = () => {
  const [credentials, setCredentials] = useState({
    email: '',
    password: ''
  });

  const handleChange = (e) => {
    setCredentials({
      ...credentials,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await loginUser(credentials);
      alert('Login successful');
  
      const { token, role } = response.data;
      localStorage.setItem('token', token);
  
      switch (role) {
        case 'user':
          window.location.href = '/user-profile';
          break;
        case 'admin':
          window.location.href = '/admin-profile';
          break;
        case 'superAdmin':
          window.location.href = '/super-admin';
          break;
        case 'platformAdmin':
          window.location.href = '/platform-admin';
          break;
        default:
          console.error('Unknown role:', role);
          break;
      }
    } catch (error) {
      console.error('Error logging in:', error);
      if (error.response) {
        console.error('Response data:', error.response.data);
        alert(error.response.data); // Display backend error message to the user
      } else {
        alert('Login failed. Please try again.'); // Generic error message for unexpected errors
      }
    }
  };

  return (
    <div className="container">
      <div className="header">
        <div className="text">Login</div>
        <div className="underline"></div>
      </div>
      <form onSubmit={handleSubmit}>
        <div className="inputs">
          <div className="input">
            <img src={user_icon} alt="user" />
            <input name="email" placeholder="Email" value={credentials.email} onChange={handleChange} />
          </div>
          <div className="input">
            <img src={password_icon} alt="pswd" />
            <input type="password" name="password" placeholder="Password" value={credentials.password} onChange={handleChange} />

          </div>
        </div>
        <div className="forgot-password">
          Forgot Password? <span>Click here</span>
        </div>

        <div className="submit-container">
          <button className="submit" type="submit">
            Login
          </button>
        </div>
      </form>
      
    </div>
  );
};
export default Login;
