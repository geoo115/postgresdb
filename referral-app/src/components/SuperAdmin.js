import React, { useState, useEffect } from 'react';
import { fetchSuperAdmin } from '../api';
import CreateCompanyForm from './CreateCompanyForm';
import CompanyList from './CompanyList';
import CreateUserForm from './CreateUserForm';
import UserList from './UserList';
import LogoutButton from './LogoutButton';
import ReferralRequestForm from './ReferralRequestForm';
import ViewReferrals from './ViewReferrals';
import ReferralsSent from './ReferralsSent';
import ReferralsReceived from './ReferralsReceived';

const SuperAdmin = () => {
  const [companies, setCompanies] = useState([]);
  const [users, setUsers] = useState([]);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const response = await fetchSuperAdmin();
      setCompanies(response.data.companies || []);
      setUsers(response.data.users || []);
    } catch (error) {
      console.error('Error fetching super admin data:', error);
    }
  };

  const refreshData = async () => {
    try {
      const response = await fetchSuperAdmin();
      setCompanies(response.data.companies || []);
      setUsers(response.data.users || []);
    } catch (error) {
      console.error('Error refreshing data:', error);
    }
  };

  return (
    <>
      <h1>Welcome Super Admin!</h1>
      <LogoutButton />
      <CreateCompanyForm refreshData={refreshData} />
      <CompanyList companies={companies} refreshData={refreshData} />
      <CreateUserForm companies={companies} refreshData={refreshData} userRole="superAdmin" />
      <UserList users={users} companies={companies} refreshData={refreshData} />
      <ReferralRequestForm />
      <ViewReferrals />
        <ReferralsSent />
        <ReferralsReceived />
    </>
  );
};

export default SuperAdmin;
