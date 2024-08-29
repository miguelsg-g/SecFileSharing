import React, { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import axiosInstance from '../services/axiosInterceptors';
import '../styles/ResetPassword.css';
import Base from '../components/Base';

const ResetPassword = () => {
    const { uidb64, token } = useParams();
    const navigate = useNavigate();
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [error, setError] = useState(null);
    const [message, setMessage] = useState(null);

    // Antes de enviar el formulario, el frontend debe verificar que las contraseñas coincidan. Si no coinciden, se debe mostrar un mensaje de error.
    // Si las contraseñas coinciden, se debe enviar la nueva contraseña al backend
    // Si la operación es exitosa, se debe mostrar un mensaje de éxito y redirigir al usuario a la página de login después de 3 segundos.
    const handleSubmit = async (e) => {
        e.preventDefault();

        if (password !== confirmPassword) {
            setError('Las contraseñas no coinciden');
            return;
        }

        try {
            await axiosInstance.post(`/reset_password/${uidb64}/${token}/`, { password, confirmPassword })
            setMessage('Contraseña cambiada con éxito. Redirigiendo a la página de login...');
            setTimeout(() => {
                navigate('/login');
            }, 3000); // Redirigir después de 3 segundos
        } catch (err) {
            // como error imprimimos el mensaje de respuesta del servidor. Para ello, al ser un JSON, accedemos a la propiedad data del objeto err.response
            setError('Error al cambiar la contraseña: ' + err.message);
        }
    };
    
    return (
        <Base>
            <div className="reset-password-container">
                <h2>Restablecer la Contraseña</h2>
                <form onSubmit={handleSubmit}>
                    <label>
                        Nueva Contraseña:
                        <p>

                        </p>
                        <input
                            type="password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            required
                        />
                    </label>
                    <label>
                        Confirmar Nueva Contraseña:
                        <input
                            type="password"
                            value={confirmPassword}
                            onChange={(e) => setConfirmPassword(e.target.value)}
                            required
                        />
                    </label>
                    <button type="submit">Restablecer Contraseña</button>
                </form>
                {error && <p className="error">{error}</p>}
                {message && <p className="message">{message}</p>}
            </div>
        </Base>
        
    );
};

export default ResetPassword;