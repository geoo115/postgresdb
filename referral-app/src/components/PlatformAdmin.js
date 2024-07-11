import React, { useState, useEffect } from 'react';
import { fetchPlatformAdmin } from '../api';
import CompanyList from './CompanyList';
import CreateUserForm from './CreateUserForm';
import UserList from './UserList';
import ReferralRequestForm from './ReferralRequestForm';
import ViewReferrals from './ViewReferrals';
import LogoutButton from './LogoutButton';

const PlatformAdmin = () => {
  const [companies, setCompanies] = useState([]);
  const [users, setUsers] = useState([]);
  const [referralRequests, setReferralRequests] = useState([]);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const response = await fetchPlatformAdmin();
      setCompanies(response.companies || []);
      setUsers(response.users || []);
      setReferralRequests(response.referrals || []);
    } catch (error) {
      console.error('Error fetching platform admin data:', error);
    }
  };

  const refreshData = async () => {
    try {
      const response = await fetchPlatformAdmin();
      setCompanies(response.companies || []);
      setUsers(response.users || []);
      setReferralRequests(response.referrals || []);
    } catch (error) {
      console.error('Error refreshing data:', error);
    }
  };

  return (
    <div>
      <h2>Welcome Platform Admin</h2>
      <LogoutButton />
      <CompanyList companies={companies} refreshData={refreshData} />
      <CreateUserForm companies={companies} refreshData={refreshData} userRole="platformAdmin" />
      <UserList users={users} refreshData={refreshData} />
      <ReferralRequestForm />
      <ViewReferrals referralRequests={referralRequests} />

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
