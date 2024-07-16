import  { useEffect, useState } from 'react';
import axios from 'axios';
import '../styles.css';

const ReceivedRefs = () => {
  const [referrals, setReferrals] = useState([]);

  useEffect(() => {
    // Fetch data for received referrals when component mounts
    const fetchReceivedReferrals = async () => {
      try {
        const response = await axios.get('http://localhost:8080/referrals-received', { withCredentials: true });
        setReferrals(response.data);
      } catch (error) {
        console.error('Error fetching received referrals:', error);
      }
    };

    fetchReceivedReferrals();
  }, []);

  const handleAction = async (referralRequestID, action) => {
    try {
      await axios.post(`http://localhost:8080/referral-request-action/${action}/${referralRequestID}`, {}, {
        withCredentials: true // Ensure credentials are sent with the request
      });
      alert(`Referral request ${action}ed successfully`);
      // Refresh the referral requests list with updated status
      setReferrals(prevRequests =>
        prevRequests.map(request =>
          request.id === referralRequestID ? { ...request, status: action === 'approve' ? 'Approved' : 'Denied' } : request
        )
      );
    } catch (error) {
      console.error(`Error ${action}ing referral request:`, error);
      alert(`Failed to ${action} referral request`);
    }
  };

  return (
    <div>
      <h2>Received Referrals</h2>
      <ul>
        {referrals.map(referral => (
          <li key={referral.id}>
            <strong>{referral.title}</strong>
            <p>{referral.content}</p>
            <p>Referee Client: {referral.referee_client}</p>
            <p>Referee Client Email: {referral.referee_client_email}</p>
            <p>Status: {referral.status}</p>
            <p>Created At: {new Date(referral.created_at).toLocaleString()}</p>
            <button onClick={() => handleAction(referral.id, 'approve')}>Accept</button>
            <button onClick={() => handleAction(referral.id, 'deny')}>Deny</button>
          </li>
        ))}
      </ul>
    </div>
  );
};

export default ReceivedRefs;
