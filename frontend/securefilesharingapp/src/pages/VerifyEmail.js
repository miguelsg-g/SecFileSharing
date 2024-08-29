import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import styled from 'styled-components';
import Base from '../components/Base.js';
const Container = styled.div`
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 50vh;
    background-color: #c4eec4;
`;

const Card = styled.div`
    background: #fff;
    padding: 40px;
    border-radius: 10px;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
    max-width: 400px;
    width: 100%;
    text-align: center;
`;

const Title = styled.h1`
    margin-bottom: 20px;
    color: #333;
`;

const Message = styled.p`
    color: ${props => props.error ? 'red' : 'green'};
    margin-top: 20px;
`;

const LoadingSpinner = styled.div`
    border: 4px solid rgba(0, 0, 0, 0.1);
    width: 36px;
    height: 36px;
    border-radius: 50%;
    border-left-color: #09f;
    animation: spin 1s ease infinite;
    margin-top: 5px;

    @keyframes spin {
        0% {
            transform: rotate(0deg);
        }
        100% {
            transform: rotate(360deg);
        }
    }
`;

function VerifyEmail() {
    const { uid, token } = useParams();
    const navigate = useNavigate();
    const [message, setMessage] = useState('');
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const verifyEmail = async () => {
            try {
                const response = await fetch(`http://localhost:8000/api/verify-email/${uid}/${token}/`, {
                    method: 'GET',
                });
                if (!response.ok) throw new Error('Email verification failed');
                setMessage('Email verified successfully. You can now log in.');
                setTimeout(() => {
                    navigate('/login');
                }, 3000);
            } catch (error) {
                setMessage(error.message || 'Email verification failed');
            } finally {
                setLoading(false);
            }
        };
        verifyEmail();
    }, [uid, token, navigate]);

    return (
        <Base>
            <Container>
                <Card>
                    <Title>Email Verification</Title>
                    <p>
                        Verifying your email. Please wait...
                    </p>
                    {loading ? <LoadingSpinner /> : <Message>{message}</Message>}
                </Card>
            </Container>
        </Base>
    );
}

export default VerifyEmail;