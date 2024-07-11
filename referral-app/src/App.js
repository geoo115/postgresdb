import React from 'react';
import { BrowserRouter as Router, Route, Routes, Link } from 'react-router-dom';
import Register from './components/Register';
import Login from './components/Login';
import UserProfile from './components/UserProfile';
import AdminProfile from './components/AdminProfile';
import PlatformAdmin from './components/PlatformAdmin';
import SuperAdmin from './components/SuperAdmin';
import CreateReferral from './components/CreateReferral';
import ViewReferrals from './components/ViewReferrals';
import './App.css';

const App = () => {
  return (
    <Router>
      <div>
        <nav>
          <ul>
            <li><Link to="/register">Register</Link></li>
            <li><Link to="/login">Login</Link></li>
            <li><Link to="/user-profile">User Profile</Link></li>
            <li><Link to="/admin-profile">Admin Profile</Link></li>
            <li><Link to="/platform-admin">Platform Admin</Link></li>
            <li><Link to="/super-admin">Super Admin</Link></li>
            <li><Link to="/create-referral">Create Referral</Link></li>
            <li><Link to="/view-referrals">View Referrals</Link></li>
          </ul>
        </nav>
        <Routes>
          <Route path="/register" element={<Register />} />
          <Route path="/login" element={<Login />} />
          <Route path="/user-profile" element={<UserProfile />} />
          <Route path="/admin-profile" element={<AdminProfile />} />
          <Route path="/platform-admin" element={<PlatformAdmin />} />
          <Route path="/super-admin" element={<SuperAdmin />} />
          <Route path="/create-referral" element={<CreateReferral />} />
          <Route path="/view-referrals" element={<ViewReferrals />} />
          <Route path="/" element={<Home />} />
        </Routes>
      </div>
    </Router>
  );
};

const Home = () => (
 <>
 <div>
    <h2>Welcome to the Referral Management System</h2>
  </div>
  <Login/>
 </> 
);

export default App;
