import axios from 'axios';

axios.defaults.withCredentials = true;

const api = axios.create({
  baseURL: 'http://localhost:8000',
  timeout: 5000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add Authorization header
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    console.error('Request Error:', error);
    return Promise.reject(error);
  }
);

// Response interceptor to log responses and handle errors
api.interceptors.response.use(
  (response) => {
    console.log('Response:', response);
    return response;
  },
  (error) => {
    console.error('Response Error:', error.response);
    return Promise.reject(error);
  }
);

// API functions for various endpoints
export const registerUser = (userData) => api.post('/register', userData);
export const loginUser = (credentials) => api.post('/login', credentials);
export const createReferralRequest = async (formData) => {
  try {
    const response = await api.post('/create-referral', formData);
    return response.data;
  } catch (error) {
    throw error;
  }
};
export const fetchReferralRequests = () => api.get('/referral-request');
export const submitReferralRequest = (request) => api.post('/submit-referral-request', request);
export const approveReferralRequest = (referralRequestID) => api.post(`/referral-request-action/approve/${referralRequestID}`);
export const denyReferralRequest = (referralRequestID) => api.post(`/referral-request-action/deny/${referralRequestID}`);
export const fetchReferralRequestByID = (referralRequestID) => api.get(`/referral-request/${referralRequestID}`);
export const fetchReferralRequestsByReferrer = (referrerUserID) => api.get(`/referral-requests/referrer/${referrerUserID}`);
export const logoutUser = () => api.post('/logout');
export const fetchUserProfile = () => api.get('/user-profile');
export const fetchAdminProfile = () => api.get('/admin-profile');
export const fetchPlatformAdmin = () => api.get('/platform-admin');
export const fetchSuperAdmin = () => api.get('/super-admin');
export const createCompany = (companyData) => api.post('/create-company', companyData);
export const deleteCompany = (companyID) => api.post('/delete-company', { company_id: companyID });
export const createUser = (userData) => api.post('/create-user', userData);
export const updateUser = async (userId, userData) => {
  try {
    const response = await api.post(`/update-user/${userId}`, userData);
    console.log('User updated successfully:', response.data);
    return response.data;
  } catch (error) {
    console.error('Error updating user:', error);
    throw error;
  }
};
export const deleteUser = (userID) => api.post('/delete-user', { user_id: userID });

export default api;
