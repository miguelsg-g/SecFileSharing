import React, { useState} from 'react';
// import { login } from '../services/authService';
import styled from 'styled-components';
import { FaUser, FaLock } from 'react-icons/fa';
import { useNavigate } from 'react-router-dom';
import authService from '../services/authService';
import Cookies from 'js-cookie';
import axiosInstance from '../services/axiosInterceptors';
import Base from '../components/Base';

const csrftoken = Cookies.get('csrftoken');
axiosInstance.defaults.headers.common['X-CSRFToken'] = csrftoken;
const Title = styled.h1`
    margin-bottom: 20px;
    color: #333;
`;

const Container = styled.div`
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 58vh;
    background-color: #f0f2f5;
`;

const Form = styled.form`
    background: #fff;
    padding: 40px;
    border-radius: 10px;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
    max-width: 400px;
    width: 100%;
    text-align: center;
`;

const InputGroup = styled.div`
    display: flex;
    align-items: center;
    margin-bottom: 20px;
    border: 1px solid #ccc;
    border-radius: 5px;
    padding: 10px;
`;

const Icon = styled.div`
    margin-right: 10px;
    color: #888;
`;

const Input = styled.input`
    border: none;
    outline: none;
    width: 100%;
    font-size: 16px;
`;

const Button = styled.button`
    background-color: #4caf50;
    color: white;
    padding: 10px 20px;
    border: none;
    border-radius: 5px;
    cursor: pointer;
    font-size: 16px;
    width: 100%;
    margin-top: 20px;
`;

const StyledLink = styled.a`
    color: #4caf50;
    text-decoration: none;
    margin-top: 20px;
    display: inline-block;
`;

const Message = styled.p`
    color: ${props => props.$error ? 'red' : 'green'};
    margin-top: 20px;
`;

function Login() {
    const [loginData, setLoginData] = useState({
        username: '',
        password: '',
        otp: '' // Nuevo campo para el OTP
    });

    const handleChange = (e) => {
        setLoginData({ ...loginData, [e.target.name]: e.target.value });
    };

    const [step, setStep] = useState(1);  // Maneja los pasos del flujo de autenticación
    const [message, setMessage] = useState(''); 
    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            if (step === 1) {
                // Enviar el nombre de usuario y la contraseña para la autenticación de dos factores
                const response = await authService.login(loginData);
                if (response.status === 200) {
                    if (response.message === 'OTP sent to your email') {
                        setMessage('OTP sent to your email');
                        setStep(2);
                    }
                }
            } else if (step === 2) {
                // Paso 2: Validar el OTP
                const response = await authService.validateOTP(loginData);
                axiosInstance.defaults.headers.common['Authorization'] = `Bearer ${response.access}`;
                localStorage.setItem('refreshToken', response.refresh);
                localStorage.setItem('authToken', response.access);
                setMessage('Login successful');
                navigate('/');
            }
        } catch (error) {
            console.error('Error logging in:', error);
            setMessage('Login failed: ' + (error.response.data.error || 'Invalid credentials'));
        }
    } 
    return (
        <Base>
            <Container>
                <Form onSubmit={handleSubmit}>
                    <Title>Login</Title>
                    {step === 2 && <p>Enter the OTP sent to your email</p>}
                    <InputGroup>
                        <Icon><FaUser /></Icon>
                        <Input
                            type="text"
                            name="username"
                            value={loginData.username}
                            onChange={handleChange}
                            placeholder="Username"
                            required
                        />
                    </InputGroup>
                    <InputGroup>
                        <Icon><FaLock /></Icon>
                        <Input
                            type="password"
                            name="password"
                            value={loginData.password}
                            onChange={handleChange}
                            placeholder="Password"
                            required
                            disabled={step === 2}
                        />
                    </InputGroup>
                    <InputGroup>
                        {step === 2 && (
                            <>
                                <Icon><FaLock /></Icon>
                                <Input
                                    type="text"
                                    name="otp"
                                    value={loginData.otp}
                                    onChange={handleChange}
                                    placeholder="OTP Token"
                                    required
                                    hidden={step === 1}
                                    disabled={step === 1}
                                />
                            </>
                        )}
                    </InputGroup>
                    <Button type="submit">{step === 1 ? 'Login' : 'Submit OTP'}</Button>
                </Form>
            </Container>
            <div> 
                <Message $error={message.includes('Login failed')}>{message}</Message>
                <StyledLink href="/forgot-password">He olvidado mi contraseña</StyledLink>
                <Message>Don't have an account? <StyledLink href="/register">Register</StyledLink></Message>
            </div>
        </Base>
    );
}

export default Login;
