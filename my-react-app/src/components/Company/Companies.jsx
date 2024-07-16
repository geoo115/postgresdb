import { useState, useEffect } from 'react';
import axios from 'axios';
import '../styles.css';

const Companies = () => {
    const [companies, setCompanies] = useState([]);
    const [loading, setLoading] = useState(false);

    useEffect(() => {
        fetchCompanies();
    }, []);

    const fetchCompanies = async () => {
        setLoading(true);
        try {
            const response = await axios.get('http://localhost:8080/companies', { withCredentials: true });
            setCompanies(response.data);
        } catch (error) {
            console.error('Error fetching companies:', error);
            alert('Failed to fetch companies: ' + (error.response?.data || error.message));
        } finally {
            setLoading(false);
        }
    };

    const handleDelete = async (companyID) => {
        if (window.confirm('Are you sure you want to delete this company?')) {
            try {
                await axios.post('http://localhost:8080/delete-company', { company_id: companyID });
                alert('Company deleted successfully');
                setCompanies(companies.filter(company => company.id !== companyID));
            } catch (error) {
                console.error('Error deleting company:', error);
                alert('Failed to delete company: ' + (error.response?.data || error.message));
            }
        }
    };

    return (
        <div>
            <h2>Companies List</h2>
            {loading && <p>Loading companies...</p>}
            <ul>
                {companies.map(company => (
                    <li key={company.id}>
                        <strong>{company.id}</strong>
                        <strong>{company.name}</strong>
                        <button onClick={() => handleDelete(company.id)}>Delete</button>
                    </li>
                ))}
            </ul>
        </div>
    );
};

export default Companies;
