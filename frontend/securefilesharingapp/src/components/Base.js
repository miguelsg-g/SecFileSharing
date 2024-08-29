import React from 'react';
import { Link } from 'react-router-dom';
import '../styles/Base.css';  // Añadimos el archivo de estilos CSS
import LogoutButton from './LogoutButton';  // Importa el componente de logout
const Base = ({ user, messages, children }) => {

    return (
        <div className="base-container">
            <header>
                <div className="header-content">
                    <h1 className="title">
                        <span className="lock-icon">🔒</span>
                        SecFileSharingApp
                    </h1>
                    {user && (
                        <nav>   
                            <Link to="/dashboard" className="nav-link">Dashboard</Link>
                            <Link to="/personal_page" className="nav-link">Personal Page</Link>
                            <LogoutButton />
                        </nav>
                    )}
                    
                </div>
            </header>
            <main>
                {messages && (
                    <div className="messages">
                        {messages.map((message, index) => (
                            <div key={index} className={`alert ${message.tags}`}>{message.text}</div>
                        ))}
                    </div>
                )}
                {children}
            </main>
        </div>
    );
};

export default Base;
