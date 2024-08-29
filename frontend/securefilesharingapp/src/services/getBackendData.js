import axiosInstance from '../services/axiosInterceptors';

// getUserData() es una función asíncrona que hace una solicitud GET a la API para obtener los datos del usuario.
const getUserData = async () => {
    try {
        const response = await axiosInstance.get(`dashboard/`);
        return response.data;
        
    } catch (error) {
        console.error('Error fetching user data:', error);
        throw error;
    }
};

// getPersonalPageData() es una función asíncrona que hace una solicitud GET a la API para obtener los datos de la página personal.
const getPersonalPageData = async () => {
    try {
        const response = await axiosInstance.get('personal_page/');
        return response.data;
    } catch (error) {
        console.error('Error fetching personal page data:', error);
        throw error;
    }
};

const getBackendData = {
    getUserData,
    getPersonalPageData,
};
export default getBackendData;
/*
        const token = localStorage.getItem('authtoken');
        if (!token) {
            throw new Error('No token found');
        }

        const response = await axios.get(`${API_URL}dashboard/`, {
            headers: {
                'Authorization': `Token ${token}`
            }
        });
        return response.data;
        */