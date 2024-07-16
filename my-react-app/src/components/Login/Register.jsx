import  { useState } from 'react';
import axios from 'axios';
import '../styles.css';

const Register = () => {
    const [formData, setFormData] = useState({
        email: '',
        username: '',
        password: '',
        role: '',
        companyName: ''
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
            const response = await axios.post('http://localhost:8080/register', formData);
            if (response.status === 201) {
                alert('User registered successfully');
            }
        } catch (error) {
            console.error('There was an error registering the user!', error);
            alert('Registration failed: ' + error.response?.data || error.message);
        }
    };

    return (
        <form onSubmit={handleSubmit}>
            <input name="email" placeholder="Email" onChange={handleChange} />
            <input name="username" placeholder="Username" onChange={handleChange} />
            <input name="password" type="password" placeholder="Password" onChange={handleChange} />
            <input name="role" placeholder="Role" onChange={handleChange} />
            <input name="companyName" placeholder="Company Name" onChange={handleChange} />
            <button type="submit">Register</button>
        </form>
    );
};

export default Register;
