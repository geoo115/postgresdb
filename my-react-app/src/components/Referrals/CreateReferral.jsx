import  { useState, useEffect } from 'react';
import axios from 'axios';
import '../styles.css';

const CreateReferral = () => {
  const [formData, setFormData] = useState({
    title: '',
    content: '',
    company_id: '', // Adjusted to match backend field name
    referee_client: '',
    referee_client_email: ''
  });
  const [companies, setCompanies] = useState([]);

  useEffect(() => {
    // Fetch the list of companies from the backend
    const fetchCompanies = async () => {
      try {
        const response = await axios.get('http://localhost:8080/companies', { withCredentials: true });
        setCompanies(response.data);
      } catch (error) {
        console.error('Error fetching companies:', error);
      }
    };
    fetchCompanies();
  }, []);

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.name === 'company_id' ? parseInt(e.target.value, 10) : e.target.value
    });
  };
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post('http://localhost:8080/create-referral', formData, {
        headers: {
          'Content-Type': 'application/json'
        },
        withCredentials: true
      });
      if (response.status === 201) {
        alert('Referral request created successfully');
        setFormData({
          title: '',
          content: '',
          company_id: '',
          referee_client: '',
          referee_client_email: ''
        });
      }
    } catch (error) {
      console.error('Error creating referral request:', error);
      alert('Failed to create referral request: ' + (error.response?.data || error.message));
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
          name="company_id" // Ensure this matches the backend field name
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

export default CreateReferral;
