import React, { useState, useEffect } from 'react';
import axios from 'axios';

const ViewReferrals = ({ userRole, userCompanyID }) => { // Assuming userCompanyID is passed as a prop
  const [referralRequests, setReferralRequests] = useState(null);

  useEffect(() => {
    const fetchReferralRequests = async () => {
      try {
        let endpoint = 'http://localhost:8000/referral-request';
        if (userRole === 'companyAdmin' || userRole === 'user') {
          // Append company ID to fetch only company-specific referrals
          endpoint += `?companyID=${userCompanyID}`;
        }

        const response = await axios.get(endpoint, {
          headers: {
            Authorization: `Bearer YOUR_AUTH_TOKEN`
          }
        });
        setReferralRequests(response.data);
      } catch (error) {
        console.error('Error fetching referral requests:', error);
      }
    };

    fetchReferralRequests();
  }, [userRole, userCompanyID]); // Ensure userRole and userCompanyID are in the dependency array if they can change

  const handleAction = async (referralRequestID, action) => {
    try {
      await axios.post(`http://localhost:8000/referral-request-action/${action}/${referralRequestID}`, {}, {
        headers: {
          Authorization: `Bearer YOUR_AUTH_TOKEN`
        }
      });
      alert(`Referral request ${action}ed successfully`);
      // Refresh the referral requests list with updated status
      setReferralRequests(prevRequests => prevRequests.map(request =>
        request.id === referralRequestID ? { ...request, status: action === 'approve' ? 'Approved' : 'Denied' } : request
      ));
    } catch (error) {
      console.error(`Error ${action}ing referral request:`, error);
      alert(`Failed to ${action} referral request`);
    }
  };

  return (
    <div>
      <h1>Referral Requests</h1>
      {referralRequests === null ? (
        <p>Loading...</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Title</th>
              <th>Content</th>
              <th>Username</th>
              <th>Referee Client</th>
              <th>Referee Client Email</th>
              <th>Created At</th>
              <th>Status</th>
              <th>Company ID</th>
              <th>Company Name</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {referralRequests.map(request => (
              <tr key={request.id}>
                <td>{request.id}</td>
                <td>{request.title}</td>
                <td>{request.content}</td>
                <td>{request.username}</td>
                <td>{request.referee_client}</td>
                <td>{request.referee_client_email}</td>
                <td>{new Date(request.created_at).toLocaleString()}</td>
                <td>{request.status}</td>
                <td>{request.company_id}</td>
                <td>{request.company_name}</td>
                <td>
                  <button onClick={() => handleAction(request.id, 'approve')}>Accept</button>
                  <button onClick={() => handleAction(request.id, 'deny')}>Deny</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
};

export default ViewReferrals;
