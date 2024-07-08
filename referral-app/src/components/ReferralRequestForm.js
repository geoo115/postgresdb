import React, { useState, useEffect } from 'react';
import { createReferralRequest, fetchSuperAdmin } from '../api';

const ReferralRequestForm = () => {
  const [formData, setFormData] = useState({
    title: '',
    content: '',
    company_name: '',
    referee_client: '',
    referee_client_email: ''
  });

  const [companies, setCompanies] = useState([]);

  useEffect(() => {
    const fetchCompanies = async () => {
      try {
        const response = await fetchSuperAdmin();
        setCompanies(response.data.companies || []);
      } catch (error) {
        console.error('Error fetching companies:', error);
      }
    };

    fetchCompanies();
  }, []);

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await createReferralRequest(formData);
      alert('Referral request created successfully');
      setFormData({
        title: '',
        content: '',
        company_name: '',
        referee_client: '',
        referee_client_email: ''
      });
    } catch (error) {
      console.error('Error creating referral request:', error);
      if (error.response) {
        console.error('Server Response Data:', error.response.data);
      }
      alert('Referral request creation failed');
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
          value={formData.title}
          onChange={handleChange}
          required
        /><br />

        <label htmlFor="content">Content:</label>
        <textarea
          id="content"
          name="content"
          value={formData.content}
          onChange={handleChange}
          required
        /><br />

        <label htmlFor="company">Company:</label>
        <select
          id="company"
          name="company_name"
          value={formData.company_id}
          onChange={handleChange}
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
          value={formData.referee_client}
          onChange={handleChange}
          required
        /><br />

        <label htmlFor="refereeClientEmail">Referee Client Email:</label>
        <input
          type="email"
          id="refereeClientEmail"
          name="referee_client_email"
          value={formData.referee_client_email}
          onChange={handleChange}
          required
        /><br />

        <button type="submit">Submit</button>
      </form>
    </div>
  );
};

export default ReferralRequestForm;
