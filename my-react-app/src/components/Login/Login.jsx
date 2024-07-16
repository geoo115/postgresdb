import  { useState } from 'react';
import axios from 'axios';
import '../styles.css';

const Login = () => {
    const [credentials, setCredentials] = useState({
        email: '',
        password: ''
    });

    const handleChange = (e) => {
        setCredentials({
            ...credentials,
            [e.target.name]: e.target.value
        });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            const response = await axios.post('http://localhost:8080/login', credentials, { withCredentials: true });
            if (response.status === 200) {
                alert('Login successful');
                window.location.href = "/referrals";
                console.log(response.data); // Handle the user data received from the response
            }
        } catch (error) {
            console.error('There was an error logging in!', error);
            alert('Login failed: ' + error.response?.data || error.message);
        }
    };

    return (
        <form onSubmit={handleSubmit}>
            <input name="email" placeholder="Email" onChange={handleChange} />
            <input name="password" type="password" placeholder="Password" onChange={handleChange} />
            <button type="submit">Login</button>
        </form>
    );
};

export default Login;
