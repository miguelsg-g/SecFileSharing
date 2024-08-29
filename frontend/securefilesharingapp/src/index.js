// src/index.js
import React from 'react';
import { createRoot } from 'react-dom/client';
import './index.css';
import App from './App';
import { BrowserRouter as Router } from 'react-router-dom';
// Change the import statement to import the App component from the correct pathimport App from './App';

const container = document.getElementById('root');
const root = createRoot(container);

root.render(
    <Router>
        <App />
    </Router>
);

// Path: SecFileSharingApp/frontend/secfilesharingapp/src/pages/Register.js
