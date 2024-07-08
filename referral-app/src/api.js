import axios from 'axios';

axios.defaults.withCredentials = true;

const api = axios.create({
  baseURL: 'http://localhost:8000',
  timeout: 5000,
  headers: {
    'Content-Type': 'application/json',
  },
});



// Add a request interceptor to include the token in the headers
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token'); // Retrieve the token from localStorage
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`; // Include the token in the Authorization header
    }
    console.log('Request Config:', config); // Log the request configuration
    return config;
  },
  (error) => {
    console.error('Request Error:', error); // Log any request errors
    return Promise.reject(error);
  }
);

// Add a response interceptor to log responses and errors
api.interceptors.response.use(
  (response) => {
    console.log('Response:', response); // Log the response
    return response;
  },
  (error) => {
    console.error('Response Error:', error.response); // Log any response errors
    return Promise.reject(error);
  }
);

export const registerUser = (userData) => api.post('/register', userData);
export const loginUser = (credentials) => api.post('/login', credentials);
export const createReferralRequest = (request) => {
  console.log('Creating referral request with data:', request);
  return api.post('/create-referral', request);
};
export const fetchReferralRequests = () => api.get('/referral-request');
export const submitReferralRequest = (request) => api.post('/submit-referral-request', request);
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
