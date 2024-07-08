import React, { useState, useEffect } from 'react';
import { createReferralRequest, fetchSuperAdmin } from '../api'; // Assuming fetchSuperAdmin retrieves companies

const ReferralRequest = () => {
  const [title, setTitle] = useState('');
  const [content, setContent] = useState('');
  const [companies, setCompanies] = useState([]);
  const [selectedCompany, setSelectedCompany] = useState('');
  const [refereeClient, setRefereeClient] = useState('');
  const [refereeClientEmail, setRefereeClientEmail] = useState('');

  useEffect(() => {
    const fetchCompanies = async () => {
      try {
        const response = await fetchSuperAdmin(); // Adjust this based on your API structure
        setCompanies(response.data.companies || []);
      } catch (error) {
        console.error('Error fetching companies:', error);
      }
    };

    fetchCompanies();
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await createReferralRequest({
        title,
        content,
        company_id: selectedCompany,
        referee_client: refereeClient,
        referee_client_email: refereeClientEmail
      });
      // Clear form fields after submission
      setTitle('');
      setContent('');
      setSelectedCompany('');
      setRefereeClient('');
      setRefereeClientEmail('');
      // Optionally, refresh the list of referral requests or perform any other updates
    } catch (error) {
      console.error('Error creating referral request:', error);
    }
  };

  return (
    <div>
      <h1>Create Referral Request</h1>
      <form onSubmit={handleSubmit}>
        <label htmlFor="title">Title:</label>
        <input
          type="text"
          id="title"
          name="title"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          required
        /><br />

        <label htmlFor="content">Content:</label>
        <textarea
          id="content"
          name="content"
          value={content}
          onChange={(e) => setContent(e.target.value)}
          required
        /><br />

        <label htmlFor="company">Company:</label>
        <select
          id="company"
          name="company"
          value={selectedCompany}
          onChange={(e) => setSelectedCompany(e.target.value)}
          required
        >
          <option value="">Select a company</option>
          {companies.map(company => (
            <option key={company.id} value={company.id}>{company.name}</option>
          ))}
        </select><br />

        <label htmlFor="refereeClient">Referee Client:</label>
        <input
          type="text"
          id="refereeClient"
          name="referee_client"
          value={refereeClient}
          onChange={(e) => setRefereeClient(e.target.value)}
          required
        /><br />

        <label htmlFor="refereeClientEmail">Referee Client Email:</label>
        <input
          type="email"
          id="refereeClientEmail"
          name="referee_client_email"
          value={refereeClientEmail}
          onChange={(e) => setRefereeClientEmail(e.target.value)}
          required
        /><br />

        <button type="submit">Submit</button>
      </form>
    </div>
  );
};

export default ReferralRequest;
