// LogoutButton.js
import React from 'react';
import { useNavigate } from 'react-router-dom';
import authService from '../services/authService';
import styled from 'styled-components';

// StyledButton es un botón con estilos CSS aplicados.
// para color de fondo, cogemos un rojo intenso
const StyledButton = styled.button`
    background-color: #ee4242;
    color: white;
    padding: 10px 20px;
    border: none;
    border-radius: 5px;
    cursor: pointer;
    font-size: 16px;
`;
const LogoutButton = () => {
    const navigate = useNavigate();
    // tiene que mandar en la solicitud de logout el token de refresco y el de acceso
    const handleLogout = async () => {
        try {
            const refresh_token = localStorage.getItem('refreshToken');
            if (!refresh_token) {
                console.error('No refresh token found');
                navigate('/login');
            }
            const response = await authService.logout(refresh_token);
            if (response.status === 205) {
                navigate('/login');
            }
            else if (response.status === 400) {
                if (localStorage.getItem('authToken')) {
                    localStorage.removeItem('authToken');
                }
                if (localStorage.getItem('refreshToken')) {
                    localStorage.removeItem('refreshToken');
                }
                console.error('The refresh token is invalid or expired, logging out');
                navigate('/login');
            }
            else {
                console.error('Failed to logout:', response);
            }
        } catch (error) {
            console.error('Failed to logout:', error);
        }
    };

    return (
        <StyledButton onClick={handleLogout}>
            Logout
        </StyledButton>
    );
};

export default LogoutButton;