import React, { useState, useEffect } from 'react';
import axios from 'axios';

const ReferralsReceived = () => {
  const [referralRequests, setReferralRequests] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchReferralsReceived = async () => {
      try {
        const response = await axios.get('http://localhost:8000/referrals-received');
        setReferralRequests(response.data || []); // Ensure data is an array
        setLoading(false);
      } catch (error) {
        console.error('Error fetching referrals received:', error);
        setReferralRequests([]); // Default to an empty array on error
        setLoading(false);
      }
    };

    fetchReferralsReceived();
  }, []);

  if (loading) {
    return <div>Loading...</div>;
  }

  return (
    <div>
      <h2>Referrals Received</h2>
      {referralRequests.length === 0 ? (
        <p>No referral requests received.</p>
      ) : (
        <ul>
          {referralRequests.map((request) => (
            <li key={request.id}>
              <strong>Title:</strong> {request.title}<br />
              <strong>Content:</strong> {request.content}<br />
              <strong>Status:</strong> {request.status}<br />
              {/* Add more fields as needed */}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
};

export default ReferralsReceived;
