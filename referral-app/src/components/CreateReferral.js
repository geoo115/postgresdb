import React, { useState } from 'react';
import { createReferralRequest } from '../api';

const CreateReferral = () => {
  const [formData, setFormData] = useState({
    title: '',
    content: '',
    referrerUserID: '',
    companyID: '',
    refereeClient: '',
    refereeClientEmail: ''
  });

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
    } catch (error) {
      console.error('Error creating referral request:', error);
      alert('Referral request creation failed');
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input name="title" placeholder="Title" value={formData.title} onChange={handleChange} />
      <textarea name="content" placeholder="Content" value={formData.content} onChange={handleChange} />
      <input name="referrerUserID" placeholder="Referrer User ID" value={formData.referrerUserID} onChange={handleChange} />
      <input name="companyID" placeholder="Company ID" value={formData.companyID} onChange={handleChange} />
      <input name="refereeClient" placeholder="Referee Client" value={formData.refereeClient} onChange={handleChange} />
      <input name="refereeClientEmail" placeholder="Referee Client Email" value={formData.refereeClientEmail} onChange={handleChange} />
      <button type="submit">Create Referral</button>
    </form>
  );
};

export default CreateReferral;
