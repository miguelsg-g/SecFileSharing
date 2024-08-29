import axios from 'axios';
import authService from './authService';

const API_URL = 'https://192.168.1.100/api/';

const axiosInstance = axios.create({
    baseURL: API_URL,
    withCredentials: true,
    timeout: 5000,
    headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }
});

const getCsrfToken = async () => {
    try {
        const response = await axios.get(`${API_URL}csrf_cookie/`);
        return response.data.csrftoken;
    } catch (error) {
        console.error('Error fetching CSRF token:', error);
        return '';
    }
};

// Interceptor para agregar el token CSRF y el token de autorización a las solicitudes
axiosInstance.interceptors.request.use(async config => {
    const authToken = localStorage.getItem('authToken');
    if (!axiosInstance.defaults.headers['X-CSRFToken']) {
        try {
            const csrfToken = await getCsrfToken();
            config.headers['X-CSRFToken'] = csrfToken;
        } catch (error) {
            console.error('Error fetching CSRF token:', error);
        }
    }

    if (authToken) {
        config.headers['Authorization'] = `Bearer ${authToken}`;
    }
    
    return config;
}, error => {
    return Promise.reject(error);
});

// Interceptor para manejar la respuesta y refrescar el token si es necesario
axiosInstance.interceptors.response.use(
    response => response,
    async error => {
        const originalRequest = error.config;
        // Manejo de errores 401 (no autenticado)
        if (error.response && error.response.status === 401 && !originalRequest._retry) {
            originalRequest._retry = true;
            try {
                const newAccessToken = await authService.refreshToken();
                localStorage.setItem('authToken', newAccessToken);
                axiosInstance.defaults.headers.common['Authorization'] = `Bearer ${newAccessToken}`;
                originalRequest.headers['Authorization'] = `Bearer ${newAccessToken}`;
                return axiosInstance(originalRequest);
            } catch (refreshError) {
                console.error('Error refreshing token:', refreshError);
                authService.logout();
                window.location.href = '/login';
                return Promise.reject(refreshError);
            }
        } 
        // Manejo de errores 403 (prohibido)
        else if (error.response.status === 403 && !originalRequest._retry) {
            originalRequest._retry = true;
            console.error('Forbidden:', error.response.data);
            window.location.href = '/login';
        }
        // Manejo de errores 500 (error interno del servidor)
        else if (error.response.status === 500) {
            console.error('Internal server error:', error.response.data);
            // Mostrar mensaje de error en lugar de redirigir
        }
        return Promise.reject(error);
    }
);

export default axiosInstance;
