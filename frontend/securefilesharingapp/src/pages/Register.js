    import React, { useState } from 'react';
import styled from 'styled-components';
import { FaUser, FaEnvelope, FaLock } from 'react-icons/fa';
import Base from '../components/Base';
// backgroundColor: '#f0f2f5' es un color de fondo gris claro.
const Container = styled.div`
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 70vh;
    background-color: #f0f2f5;
    padding-top: 1vh;
    padding-bottom: 1vh;
`;
// Styled components nos permite definir componentes de React con estilos CSS en el mismo archivo de JavaScript.
// En este caso, Container es un div con estilos CSS aplicados.
// Los estilos CSS se definen entre comillas invertidas y se pasan como argumento a la función styled.div.
// Form es un formulario con estilos CSS aplicados.
const Form = styled.form`
    background: #fff;
    padding: 40px;
    border-radius: 10px;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
    max-width: 400px;
    width: 100%;
    text-align: center;
`;

const Title = styled.h1`
    margin-top: 1px;
    margin-bottom: 10px;
    color: #333;
`;
// InputGroup es un div con estilos CSS aplicados. Contiene un icono y un input.
const InputGroup = styled.div`
    display: flex;
    align-items: center;
    margin-bottom: 20px;
    border: 1px solid #ccc;
    border-radius: 5px;
    padding: 10px;
`;
// Icon es un div con estilos CSS aplicados. Contiene un icono de FontAwesome.
const Icon = styled.div`
    margin-right: 10px;
    color: #888;
`;
// Input es un input con estilos CSS aplicados. No tiene borde ni outline y tiene un tamaño de fuente de 16px.
const Input = styled.input`
    border: none;
    outline: none;
    width: 100%;
    font-size: 16px;
`;
// Definimos una vista para enlace al login si ya tienes cuenta. Para ello, creamos un componente Link.
// Link es un componente de React que renderiza un enlace a otra página.
// StyledLink es un componente de React con estilos CSS aplicados.
// StyledLink es un enlace con estilos CSS aplicados.
const StyledLink = styled.a`
    color: #4caf50;
    text-decoration: none;
    margin-top: 20px;
    display: inline-block;
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

// Definimos tambien un mensaje de error o éxito. Para ello, creamos un componente Message.
// Message es un componente de React con estilos CSS aplicados.
// Message es un párrafo con estilos CSS aplicados.
const Message = styled.p`
    color: ${props => props.error ? 'red' : 'green'};
    margin-top: 1px;
`;

function Register() {
    // controlamos que sea obligatorio rellenar los campos mediante el atributo required en los inputs. Por ejemplo, username: <input type="text" name="username" value={formData.username} onChange={handleChange} placeholder="Username" required />
    const [formData, setFormData] = useState({
        username: '',
        email: '',
        password1: '',
        password2: '',
    });

    const [message, setMessage] = useState('');

    const handleChange = (e) => {
        setFormData({ ...formData, [e.target.name]: e.target.value });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            const response = await fetch('https://192.168.1.100/api/register/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(formData),
            });
            // Error() muestra un mensaje de error en la consola del navegador.
            if (!response.ok) throw new Error('Failed to register');
            const data = await response.json();
            setMessage(data.message || 'User registered');
        } catch (error) {
            setMessage(error.message || 'Error al registrar usuario');
        }
    };

    return (
        <Base>
            <Container>
                <Form onSubmit={handleSubmit}>
                    <Title>Register</Title>
                    <InputGroup>
                        <Icon><FaUser /></Icon>
                        <Input
                            type="text"
                            name="username"
                            value={formData.username}
                            onChange={handleChange}
                            placeholder="Username"
                            required
                        />
                    </InputGroup>
                    <InputGroup>
                        <Icon><FaEnvelope /></Icon>
                        <Input
                            type="email"
                            name="email"
                            value={formData.email}
                            onChange={handleChange}
                            placeholder="Email"
                            required   
                        />
                    </InputGroup>
                    <InputGroup>
                        <Icon><FaLock /></Icon>
                        <Input
                            type="password"
                            name="password1"
                            value={formData.password1}
                            onChange={handleChange}
                            placeholder="Password"
                            required
                        />
                    </InputGroup>
                    <InputGroup>
                        <Icon><FaLock /></Icon>
                        <Input
                            type="password"
                            name="password2"
                            value={formData.password2}
                            onChange={handleChange}
                            placeholder="Confirm Password"
                            required
                        />
                    </InputGroup>
                    <Button type="submit">Register</Button>
                    {message && <Message>{message}</Message>}
                </Form>
            </Container>
            {message && <p>{message}</p>}
            <div>
                <Message>Already registered? <StyledLink href="/login">Login</StyledLink></Message>
            </div>
        </Base>
    );   
}

export default Register;