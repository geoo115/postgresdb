import { useState } from 'react';
import axios from 'axios';
import '../styles.css';
import Companies from './Companies';

const CreateCompany = () => {
  const [company, setCompany] = useState({
    name: ''
  });

  const handleChange = (e) => {
    setCompany({ ...company, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await axios.post('http://localhost:8080/create-company', company);
      alert('Company created successfully');
      setCompany({
        name: ''
      });
    } catch (error) {
      console.error('Error creating company:', error);
      alert('Failed to create company');
    }
  };

  return (
    <div>
      <h2>Create Company</h2>
      <form onSubmit={handleSubmit}>
        <label>Company Name:</label>
        <input type="text" name="name" value={company.name} onChange={handleChange} required />
        <br />
        <button type="submit">Create Company</button>
      </form>
      <Companies/>
    </div>
  );
};

export default CreateCompany;
