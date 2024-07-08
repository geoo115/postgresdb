import React, { useEffect, useState } from 'react';
import axios from 'axios';

const UserProfile = () => {
    const [profile, setProfile] = useState({
        email: '',
        username: '',
        role: '',
        company: '',
    });

    const fetchProfile = async () => {
        try {
            const response = await axios.get('http://localhost:8000/user-profile', { withCredentials: true });
            const data = response.data;

            if (data) {
                setProfile({
                    email: data.email,
                    username: data.username,
                    role: data.role,
                    company: data.company,
                });
            }
        } catch (error) {
            console.error("Error fetching user profile:", error);
        }
    };

    useEffect(() => {
        fetchProfile();
    }, []);

    return (
        <div>
            <h1>User Profile</h1>
            <p>Email: {profile.email}</p>
            <p>Username: {profile.username}</p>
            <p>Role: {profile.role}</p>
            <p>Company: {profile.company}</p>
        </div>
    );
};

export default UserProfile;
