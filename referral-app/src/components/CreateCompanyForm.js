import React, { useState } from 'react';
import { createCompany } from '../api';

const CreateCompanyForm = ({ refreshData }) => {
  const [newCompanyName, setNewCompanyName] = useState('');

  const handleCreateCompany = async (e) => {
    e.preventDefault();
    try {
      await createCompany({ name: newCompanyName });
      setNewCompanyName('');
      refreshData();
    } catch (error) {
      console.error('Error creating company:', error);
    }
  };

  return (
    <section>
      <h2>Create New Company</h2>
      <form onSubmit={handleCreateCompany}>
        <label htmlFor="company-name">Company Name:</label>
        <input
          type="text"
          id="company-name"
          value={newCompanyName}
          onChange={(e) => setNewCompanyName(e.target.value)}
          required
        />
        <button type="submit">Create Company</button>
      </form>
    </section>
  );
};

export default CreateCompanyForm;
