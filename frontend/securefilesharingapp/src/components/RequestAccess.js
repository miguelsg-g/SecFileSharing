import React, { useState } from 'react';
import axiosInstance from '../services/axiosInterceptors';
import '../styles/RequestAccess.css';

const RequestAccess = ({ groupId }) => {
    const [error, setError] = useState(null);
    const [message, setMessage] = useState(null);

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            const response = await axiosInstance.post(`/request_access/${groupId}/`, { requested_group: groupId });
            setMessage(response.data.message);
        } catch (error) {
            setError('Error requesting access: ' + error.message || "Error requesting access");
        }
    };

    return (
        <div className="request-access-container">
            <h2>Solicitar acceso al grupo</h2>
            <button className="btn" onClick={handleSubmit}>Solicitar Acceso</button>
            {message && <p className="success">{message}</p>}
            {error && <p className="error">{error}</p>}
        </div>
    );
};

export default RequestAccess;