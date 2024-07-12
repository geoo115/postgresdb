import React, { useState, useEffect } from 'react';
import axios from 'axios';

const ReferralsSent = () => {
  const [referralRequests, setReferralRequests] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchReferralsSent = async () => {
      try {
        const response = await axios.get('http://localhost:8000/referrals-sent');
        setReferralRequests(response.data || []);  // Ensure data is an array
        setLoading(false);
      } catch (error) {
        console.error('Error fetching referrals sent:', error);
        setReferralRequests([]);  // Default to an empty array on error
        setLoading(false);
      }
    };

    fetchReferralsSent();
  }, []);

  if (loading) {
    return <div>Loading...</div>;
  }

  return (
    <div>
      <h2>Referrals Sent</h2>
      {referralRequests.length === 0 ? (
        <p>No referral requests sent.</p>
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

export default ReferralsSent;
