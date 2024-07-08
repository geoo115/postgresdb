// CompanyList.js
import React from 'react';
import { deleteCompany } from '../api';

const CompanyList = ({ companies, refreshData }) => {
  const handleDeleteCompany = async (companyId) => {
    try {
      await deleteCompany(companyId);
      refreshData();
    } catch (error) {
      console.error('Error deleting company:', error);
    }
  };

  return (
    <section>
      <h2>Existing Companies</h2>
      {companies.length > 0 ? (
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Name</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {companies.map(company => (
              <tr key={company.id}>
                <td>{company.id}</td>
                <td>{company.name}</td>
                <td>
                  <button onClick={() => handleDeleteCompany(company.id)}>Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p>No companies found.</p>
      )}
    </section>
  );
};

export default CompanyList;
