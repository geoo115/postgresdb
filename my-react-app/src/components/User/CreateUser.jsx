import { useState } from 'react';
import axios from 'axios';
import PropTypes from 'prop-types';
import UserList from './UserList';

const CreateUser = ({ companies, refreshData }) => {
    const [newUser, setNewUser] = useState({
        email: '',
        username: '',
        password: '',
        role: 'user',
        company_id: ''
    });
    const [error] = useState(null);

    const handleCreateUser = async (e) => {
        e.preventDefault();
        try {
            const userToCreate = { ...newUser, company_id: parseInt(newUser.company_id) };
            await axios.post('http://localhost:8080/create-user', userToCreate);
            setNewUser({
                email: '',
                username: '',
                password: '',
                role: 'user',
                company_id: ''
            });
            refreshData(); // Refresh data after creating user
            alert('User created successfully');
        } catch (error) {
            console.error('Error creating user:', error);
            alert('Failed to create user');
        }
    };

    if (error) {
        return <div>Error: {error}</div>;
    }

    if (!companies || companies.length === 0) {
        return <div>Loading companies...</div>;
    }

    return (
        <section>
            <h2>Create New User</h2>
            <form onSubmit={handleCreateUser}>
                <label htmlFor="user-email">Email:</label>
                <input
                    type="email"
                    id="user-email"
                    value={newUser.email}
                    onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
                    required
                /><br />

                <label htmlFor="user-username">Username:</label>
                <input
                    type="text"
                    id="user-username"
                    value={newUser.username}
                    onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
                    required
                /><br />

                <label htmlFor="user-password">Password:</label>
                <input
                    type="password"
                    id="user-password"
                    value={newUser.password}
                    onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                    required
                /><br />

                <label htmlFor="user-role">Role:</label>
                <select
                    id="user-role"
                    value={newUser.role}
                    onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}
                    required
                >
                    <option value="platformAdmin">Platform Admin</option>
                    <option value="companyAdmin">Company Admin</option>
                    <option value="user">Standard User</option>
                </select><br />

                <div>
                    <label htmlFor="user-company">Company:</label>
                    <select
                        id="user-company"
                        value={newUser.company_id}
                        onChange={(e) => setNewUser({ ...newUser, company_id: e.target.value })}
                        required
                    >
                        <option value="">Select a company</option>
                        {companies.map(company => (
                            <option key={company.id} value={company.id}>{company.name}</option>
                        ))}
                    </select><br />
                </div>

                <button type="submit">Create User</button>
            </form>
            <UserList/>
        </section>
    );
};

CreateUser.propTypes = {
    companies: PropTypes.array.isRequired,
    refreshData: PropTypes.func.isRequired,
};

export default CreateUser;
