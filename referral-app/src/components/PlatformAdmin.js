import React, { useState, useEffect } from 'react';
import { fetchPlatformAdmin } from '../api';
import CreateUserForm from './CreateUserForm';
import UserList from './UserList';
import LogoutButton from './LogoutButton';
import ReferralRequest from './ReferralRequest';
import ViewReferrals from './ViewReferrals';
import CompanyList from './CompanyList';

const PlatformAdmin = () => {
  const [companies, setCompanies] = useState([]);
  const [users, setUsers] = useState([]);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const response = await fetchPlatformAdmin();
      setCompanies(response.data.companies || []);
      setUsers(response.data.users || []);
    } catch (error) {
      console.error('Error fetching platform admin data:', error);
    }
  };

  const refreshData = async () => {
    try {
      const response = await fetchPlatformAdmin();
      setCompanies(response.data.companies || []);
      setUsers(response.data.users || []);
    } catch (error) {
      console.error('Error refreshing data:', error);
    }
  };

  return (
    <div>
      <h2>Welcome Platform Admin</h2>
      <LogoutButton />
      <CompanyList companies={companies} refreshData={refreshData} />
      <CreateUserForm
        companies={companies}
        refreshData={refreshData}
        userRole="platformAdmin"
      />
      <UserList users={users} refreshData={refreshData} />
      <ReferralRequest />
      <ViewReferrals />
      {/* Optional: Display list of companies as a sanity check */}
      <ul>
        {companies.map(company => (
          <li key={company.id}>{company.name}</li>
        ))}
      </ul>
    </div>
  );
};

export default PlatformAdmin;
