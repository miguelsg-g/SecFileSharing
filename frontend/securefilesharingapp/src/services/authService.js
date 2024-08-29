import axiosInstance from './axiosInterceptors';
//import Cookies from 'js-cookie';

const register = async (userData) => {
    try {
        const response = await axiosInstance.post(`register/`, userData);
        return response.data;
    } catch (error) {
        console.error('Error registering user:', error.response.data);
        throw error;
    }
};

const login = async (loginData) => {
    try {
        const response = await axiosInstance.post(`token/`, loginData, { withCredentials: true }); // withCredentials: true para enviar cookies al servidor
        return response.data;
    } catch (error) {
        console.error('Error logging in:', error.response.data);
        throw error;
    }
};

const refreshToken = async () => {
    try {
        console.log('Refreshing token...')
        const response = await axiosInstance.post('token/refresh/', {
            refresh: localStorage.getItem('refreshToken') || ''
        });
        const { access } = response.data;
        localStorage.setItem('authToken', access);
        return access;
    } catch (error) {
        console.error('Error refreshing token:', error);
        throw error;
    }
};

const validateOTP = async (loginData) => {
    try {
        const response = await axiosInstance.post(`token/`, loginData, { withCredentials: true });
        return response.data;
    } catch (error) {
        console.error('Error validating OTP:', error.response.data);
        throw error;
    }
};

const logout = async (refresh_token) => {
    try {
        // mandamos refresh token en el cuerpo del mensaje para desactivarlo
        const response = await axiosInstance.post(`logout/`, 
            { refresh_token: refresh_token}, 
            { withCredentials: true }
        );
        localStorage.removeItem('authToken');
        localStorage.removeItem('refreshToken');
        delete axiosInstance.defaults.headers.common['Authorization'];
        return response;
    } catch (error) {
        console.error('Error logging out:', error);
        throw error;
    }
};


const authService = {
    register,
    login,
    logout,
    refreshToken,
    validateOTP,
};
export  default authService;
