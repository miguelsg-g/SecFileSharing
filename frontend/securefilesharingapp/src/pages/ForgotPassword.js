import React, { useState } from 'react';
import axiosInstance from '../services/axiosInterceptors';
import '../styles/ForgotPassword.css';
import Base from '../components/Base';

const ForgotPassword = () => {
    const [email, setEmail] = useState('');
    const [message, setMessage] = useState('');
    const [error, setError] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            const response = await axiosInstance.post('/password-reset-request/', { email });
            setMessage(response.data.message);
            setError('');
        } catch (err) {
            setError('Error sending password reset email.');
            setMessage('');
        }
    };

    return (
        <Base>
            <div className="forgot-password-container">
                <h2>Recuperar contraseña</h2>
                <form onSubmit={handleSubmit}>
                    <label htmlFor="email">Correo electrónico:</label>
                    <input
                        type="email"
                        id="email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        required
                    />
                    <button type="submit">Enviar</button>
                </form>
                {message && <p className="message">{message}</p>}
                {error && <p className="error">{error}</p>}
            </div>
        </Base>
    );
};

export default ForgotPassword;
