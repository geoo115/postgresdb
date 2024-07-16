import  { useState, useEffect } from 'react';
import axios from 'axios';
import '../styles.css';

const SentRefs = () => {
  const [referrals, setReferrals] = useState([]);

  useEffect(() => {
    const fetchReferrals = async () => {
      try {
        const response = await axios.get('http://localhost:8080/referrals-sent', { withCredentials: true });
        setReferrals(response.data);
      } catch (error) {
        console.error('Error fetching referral requests:', error);
        // Handle error: display message or retry mechanism
      }
    };

    fetchReferrals();
  }, []);

  return (
    <div>
      <h1>Referral Requests Sent</h1>
      {referrals.length === 0 ? (
        <p>No referral requests sent.</p>
      ) : (
        <ul>
          {referrals.map(referral => (
            <li key={referral.id}>
              <strong>Title:</strong> {referral.title}<br />
              <strong>Content:</strong> {referral.content}<br />
              <strong>Company:</strong> {referral.company_name}<br />
              <strong>Referee Client:</strong> {referral.referee_client}<br />
              <strong>Referee Client Email:</strong> {referral.referee_client_email}<br />
              <strong>Status:</strong> {referral.status}<br />
              <hr />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
};

export default SentRefs;
